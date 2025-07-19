<#
.SYNOPSIS
    Quick Security Check - Performs rapid security assessment of Windows systems

.DESCRIPTION
    This script performs a quick security scan of Windows systems, checking for:
    - Recent remote logins (RDP/SSH)
    - Suspicious running processes
    - Active external network connections
    - Recently created scheduled tasks
    - Suspicious startup items
    
    All findings are logged to daily rolling log files in the logs/ directory.

.PARAMETER LogDirectory
    Directory where log files will be stored. Defaults to "logs" subdirectory.

.PARAMETER NoConsoleOutput
    Suppresses console output. Logs will still be written to file.

.PARAMETER ShowAllProcesses
    Shows all processes, not just suspicious ones.

.PARAMETER ShowAllConnections
    Shows all network connections, not just external ones.

.PARAMETER DaysBack
    Number of days to look back for scheduled tasks. Default is 7.

.PARAMETER Help
    Displays this help message.

.PARAMETER SkipClaudeAnalysis
    Skip Claude Code AI analysis of results (if Claude Code is installed).

.EXAMPLE
    .\quick_security_check.ps1
    Runs a standard quick security check with default settings.

.EXAMPLE
    .\quick_security_check.ps1 -NoConsoleOutput
    Runs security check with output only to log file.

.EXAMPLE
    .\quick_security_check.ps1 -ShowAllProcesses -DaysBack 30
    Shows all processes and checks scheduled tasks from last 30 days.

.NOTES
    Author: Windows Security Audit Tool
    Requires: PowerShell 5.0 or higher, Administrator privileges
    Version: 1.1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogDirectory = "logs",
    
    [Parameter(Mandatory=$false)]
    [switch]$NoConsoleOutput,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowAllProcesses,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowAllConnections,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,365)]
    [int]$DaysBack = 7,
    
    [Parameter(Mandatory=$false)]
    [switch]$Help,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipClaudeAnalysis
)

# Show help if requested
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Definition -Detailed
    exit 0
}

# Check for administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

# Import logging module
. "$PSScriptRoot\Write-SecurityLog.ps1"

# Override log directory if specified
if ($LogDirectory -ne "logs") {
    $script:LogDirectory = $LogDirectory
}

# Start audit log
Start-SecurityAuditLog -LogBaseName "quick_security_check" -AuditType "Quick Security Scan"

try {
    # 1. Check for recent RDP logins
    Write-SecurityLog -Message "[1] Recent Remote Logins (RDP/SSH):" -Level 'Warning' -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    $rdpLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object {$_.Message -match 'Logon Type:\s+(10|3)'} |
        Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[8].Value}} -First 5

    if ($rdpLogins) {
        $rdpLogins | Write-SecurityLogTable -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    } else {
        Write-SecurityLog -Message "No recent remote logins found" -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    }

    # 2. Check running suspicious processes
    Write-SecurityLog -Message " " -LogBaseName "quick_security_check" -Raw
    Write-SecurityLog -Message "[2] Suspicious Processes Running:" -Level 'Warning' -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    
    if ($ShowAllProcesses) {
        $processes = Get-Process | Select-Object ProcessName, Id, StartTime, Path
        Write-SecurityLog -Message "Showing all processes" -Level 'Info' -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    } else {
        $processes = Get-Process | Where-Object {$_.ProcessName -match 'nc|ncat|netcat|mimikatz|psexec|wmic|powershell|cmd'} |
            Select-Object ProcessName, Id, StartTime, Path
    }

    if ($processes) {
        if (-not $ShowAllProcesses -and $processes.Count -gt 0) {
            Write-SecurityLog -Message "ALERT: Suspicious processes detected!" -Level 'Alert' -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
        }
        $processes | Write-SecurityLogTable -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    } else {
        Write-SecurityLog -Message "No suspicious processes found" -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    }

    # 3. Check network connections
    Write-SecurityLog -Message " " -LogBaseName "quick_security_check" -Raw
    Write-SecurityLog -Message "[3] Active Network Connections (External):" -Level 'Warning' -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    
    if ($ShowAllConnections) {
        $connections = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} |
            Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess, @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
        Write-SecurityLog -Message "Showing all established connections" -Level 'Info' -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    } else {
        $connections = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notmatch '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' -and $_.RemoteAddress -ne '::1'} |
            Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess, @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
    }

    if ($connections) {
        $connections | Write-SecurityLogTable -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    } else {
        Write-SecurityLog -Message "No external connections found" -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    }

    # 4. Check scheduled tasks created recently
    Write-SecurityLog -Message " " -LogBaseName "quick_security_check" -Raw
    Write-SecurityLog -Message "[4] Recently Created Scheduled Tasks (Last $DaysBack days):" -Level 'Warning' -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    $recentTasks = Get-ScheduledTask | Where-Object {$_.Date -gt (Get-Date).AddDays(-$DaysBack)} |
        Select-Object TaskName, Author, Date

    if ($recentTasks) {
        $recentTasks | Write-SecurityLogTable -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    } else {
        Write-SecurityLog -Message "No recently created scheduled tasks found" -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    }

    # 5. Check startup programs
    Write-SecurityLog -Message " " -LogBaseName "quick_security_check" -Raw
    Write-SecurityLog -Message "[5] Suspicious Startup Items:" -Level 'Warning' -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    $suspiciousStartup = Get-CimInstance Win32_StartupCommand | 
        Where-Object {$_.Command -match 'powershell|cmd|wscript|cscript|mshta'} |
        Select-Object Name, Command, Location

    if ($suspiciousStartup) {
        Write-SecurityLog -Message "ALERT: Suspicious startup items detected!" -Level 'Alert' -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
        $suspiciousStartup | Write-SecurityLogTable -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    } else {
        Write-SecurityLog -Message "No suspicious startup items found" -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    }

    # Complete audit log
    Complete-SecurityAuditLog -LogBaseName "quick_security_check" -AuditType "Quick Security Scan"
    
    # Display log location
    $logPath = Join-Path $PSScriptRoot $LogDirectory
    $logFile = "quick_security_check_$(Get-Date -Format 'yyyy-MM-dd').log"
    $fullLogPath = Join-Path $logPath $logFile
    Write-Host "`nLog file saved to: $fullLogPath" -ForegroundColor Green
    
    # Run Claude analysis if available and not skipped
    if (-not $SkipClaudeAnalysis) {
        Invoke-ClaudeAnalysis -LogFile $fullLogPath -AuditType "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    }

} catch {
    Write-SecurityLog -Message "ERROR: $($_.Exception.Message)" -Level 'Error' -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    Write-SecurityLog -Message "Stack trace: $($_.ScriptStackTrace)" -Level 'Error' -LogBaseName "quick_security_check" -NoConsoleOutput:$NoConsoleOutput
    exit 1
}