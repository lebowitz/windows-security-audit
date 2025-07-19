<#
.SYNOPSIS
    Comprehensive Security Audit - Deep security analysis of Windows systems

.DESCRIPTION
    This script performs a comprehensive security audit of Windows systems, analyzing:
    - Failed login attempts (brute force detection)
    - New user account creation
    - Suspicious PowerShell activity
    - New service installations
    - Suspicious process creation
    - RDP connection history
    
    The script searches for potential Indicators of Compromise (IOCs) and logs
    all findings to daily rolling log files.

.PARAMETER LogDirectory
    Directory where log files will be stored. Defaults to "logs" subdirectory.

.PARAMETER NoConsoleOutput
    Suppresses console output. Logs will still be written to file.

.PARAMETER FailedLoginHours
    Hours to look back for failed login attempts. Default is 24.

.PARAMETER NewUserDays
    Days to look back for new user accounts. Default is 7.

.PARAMETER ServiceDays
    Days to look back for new service installations. Default is 7.

.PARAMETER ProcessHours
    Hours to look back for suspicious process creation. Default is 24.

.PARAMETER RDPDays
    Days to look back for RDP connections. Default is 7.

.PARAMETER MaxEvents
    Maximum number of events to retrieve per category. Default is 1000.

.PARAMETER SkipPowerShell
    Skip PowerShell activity analysis (useful if legitimate PowerShell usage is high).

.PARAMETER ExportCSV
    Export findings to CSV files in addition to standard logging.

.PARAMETER Help
    Displays this help message.

.PARAMETER SkipClaudeAnalysis
    Skip Claude Code AI analysis of results (if Claude Code is installed).

.EXAMPLE
    .\comprehensive_audit.ps1
    Runs a comprehensive audit with default settings.

.EXAMPLE
    .\comprehensive_audit.ps1 -FailedLoginHours 48 -ExportCSV
    Checks failed logins from last 48 hours and exports findings to CSV.

.EXAMPLE
    .\comprehensive_audit.ps1 -NoConsoleOutput -LogDirectory "C:\SecurityLogs"
    Runs audit silently with logs saved to specified directory.

.EXAMPLE
    .\comprehensive_audit.ps1 -SkipPowerShell -MaxEvents 5000
    Runs audit without PowerShell checks and increases event limit.

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
    [ValidateRange(1,168)]
    [int]$FailedLoginHours = 24,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,365)]
    [int]$NewUserDays = 7,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,365)]
    [int]$ServiceDays = 7,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,168)]
    [int]$ProcessHours = 24,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,365)]
    [int]$RDPDays = 7,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(100,10000)]
    [int]$MaxEvents = 1000,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipPowerShell,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportCSV,
    
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

# Create CSV export directory if needed
if ($ExportCSV) {
    $csvPath = Join-Path $PSScriptRoot "csv_exports"
    if (!(Test-Path $csvPath)) {
        New-Item -ItemType Directory -Path $csvPath -Force | Out-Null
    }
    $csvTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
}

# Start audit log
Start-SecurityAuditLog -LogBaseName "comprehensive_audit" -AuditType "Windows Security Audit Log Check"
Write-SecurityLog -Message "Checking for potential Indicators of Compromise (IOCs)..." -Level 'Warning' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
Write-SecurityLog -Message "Parameters: FailedLoginHours=$FailedLoginHours, NewUserDays=$NewUserDays, ServiceDays=$ServiceDays, ProcessHours=$ProcessHours, RDPDays=$RDPDays, MaxEvents=$MaxEvents" -Level 'Info' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput

try {
    # 1. Check failed login attempts
    Write-SecurityLog -Message " " -LogBaseName "comprehensive_audit" -Raw
    Write-SecurityLog -Message "[1] FAILED LOGIN ATTEMPTS (Last $FailedLoginHours hours):" -Level 'Warning' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    
    $failedLogins = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4625
        StartTime=(Get-Date).AddHours(-$FailedLoginHours)
    } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue | 
        Select-Object TimeCreated, 
                      @{N='Account';E={$_.Properties[5].Value}}, 
                      @{N='Source';E={$_.Properties[19].Value}},
                      @{N='FailureReason';E={$_.Properties[8].Value}}

    if ($failedLogins) {
        Write-SecurityLog -Message "ALERT: Failed login attempts detected!" -Level 'Alert' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        $failedLogins | Write-SecurityLogTable -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        
        if ($ExportCSV) {
            $failedLogins | Export-Csv -Path "$csvPath\failed_logins_$csvTimestamp.csv" -NoTypeInformation
            Write-SecurityLog -Message "Exported to: $csvPath\failed_logins_$csvTimestamp.csv" -Level 'Info' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        }
    } else {
        Write-SecurityLog -Message "No failed login attempts found." -Level 'Success' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    }

    # 2. Check for new user accounts
    Write-SecurityLog -Message " " -LogBaseName "comprehensive_audit" -Raw
    Write-SecurityLog -Message "[2] NEW USER ACCOUNTS (Last $NewUserDays days):" -Level 'Warning' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    
    $newUsers = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4720
        StartTime=(Get-Date).AddDays(-$NewUserDays)
    } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, 
                      @{N='NewAccount';E={$_.Properties[0].Value}}, 
                      @{N='CreatedBy';E={$_.Properties[4].Value}},
                      @{N='Domain';E={$_.Properties[1].Value}}

    if ($newUsers) {
        Write-SecurityLog -Message "ALERT: New user accounts detected!" -Level 'Alert' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        $newUsers | Write-SecurityLogTable -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        
        if ($ExportCSV) {
            $newUsers | Export-Csv -Path "$csvPath\new_users_$csvTimestamp.csv" -NoTypeInformation
            Write-SecurityLog -Message "Exported to: $csvPath\new_users_$csvTimestamp.csv" -Level 'Info' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        }
    } else {
        Write-SecurityLog -Message "No new user accounts created." -Level 'Success' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    }

    # 3. Check for suspicious PowerShell activity
    if (-not $SkipPowerShell) {
        Write-SecurityLog -Message " " -LogBaseName "comprehensive_audit" -Raw
        Write-SecurityLog -Message "[3] POWERSHELL ACTIVITY:" -Level 'Warning' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        
        $psEvents = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-PowerShell/Operational'
            ID=4104
            StartTime=(Get-Date).AddHours(-$ProcessHours)
        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue |
            Where-Object {$_.Message -match 'download|invoke-expression|encodedcommand|hidden|bypass|iex|webclient|downloadstring|downloadfile'} |
            Select-Object TimeCreated, 
                          @{N='User';E={$_.UserId}},
                          @{N='Suspicious Command';E={($_.Message -split "`n")[0..2] -join " " | ForEach-Object {$_.Substring(0, [Math]::Min($_.Length, 200))}}},
                          LevelDisplayName

        if ($psEvents) {
            Write-SecurityLog -Message "CRITICAL: Suspicious PowerShell commands detected!" -Level 'Error' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
            $psEvents | Write-SecurityLogList -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
            
            if ($ExportCSV) {
                $psEvents | Export-Csv -Path "$csvPath\suspicious_powershell_$csvTimestamp.csv" -NoTypeInformation
                Write-SecurityLog -Message "Exported to: $csvPath\suspicious_powershell_$csvTimestamp.csv" -Level 'Info' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
            }
        } else {
            Write-SecurityLog -Message "No suspicious PowerShell activity found." -Level 'Success' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        }
    } else {
        Write-SecurityLog -Message " " -LogBaseName "comprehensive_audit" -Raw
        Write-SecurityLog -Message "[3] POWERSHELL ACTIVITY: Skipped" -Level 'Info' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    }

    # 4. Check for service installations
    Write-SecurityLog -Message " " -LogBaseName "comprehensive_audit" -Raw
    Write-SecurityLog -Message "[4] NEW SERVICE INSTALLATIONS (Last $ServiceDays days):" -Level 'Warning' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    
    $newServices = Get-WinEvent -FilterHashtable @{
        LogName='System'
        ID=7045
        StartTime=(Get-Date).AddDays(-$ServiceDays)
    } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, 
                      @{N='ServiceName';E={$_.Properties[0].Value}}, 
                      @{N='ServiceFile';E={$_.Properties[1].Value}},
                      @{N='ServiceType';E={$_.Properties[2].Value}},
                      @{N='ServiceAccount';E={$_.Properties[4].Value}}

    if ($newServices) {
        Write-SecurityLog -Message "ALERT: New services installed!" -Level 'Alert' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        $newServices | Write-SecurityLogTable -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        
        if ($ExportCSV) {
            $newServices | Export-Csv -Path "$csvPath\new_services_$csvTimestamp.csv" -NoTypeInformation
            Write-SecurityLog -Message "Exported to: $csvPath\new_services_$csvTimestamp.csv" -Level 'Info' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        }
    } else {
        Write-SecurityLog -Message "No new services installed." -Level 'Success' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    }

    # 5. Check for unusual process creation
    Write-SecurityLog -Message " " -LogBaseName "comprehensive_audit" -Raw
    Write-SecurityLog -Message "[5] SUSPICIOUS PROCESS CREATION (Last $ProcessHours hours):" -Level 'Warning' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    
    $suspiciousProcs = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4688
        StartTime=(Get-Date).AddHours(-$ProcessHours)
    } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue |
        Where-Object {$_.Message -match 'cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe|certutil\.exe|bitsadmin\.exe'} |
        Select-Object TimeCreated, 
                      @{N='Process';E={$_.Properties[5].Value}},
                      @{N='ParentProcess';E={$_.Properties[13].Value}},
                      @{N='User';E={$_.Properties[1].Value}} -First 50

    if ($suspiciousProcs) {
        Write-SecurityLog -Message "ALERT: Suspicious process creation detected!" -Level 'Alert' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        $suspiciousProcs | Write-SecurityLogTable -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        
        if ($ExportCSV) {
            $suspiciousProcs | Export-Csv -Path "$csvPath\suspicious_processes_$csvTimestamp.csv" -NoTypeInformation
            Write-SecurityLog -Message "Exported to: $csvPath\suspicious_processes_$csvTimestamp.csv" -Level 'Info' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        }
    } else {
        Write-SecurityLog -Message "No suspicious process creation found." -Level 'Success' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    }

    # 6. Check for RDP connections
    Write-SecurityLog -Message " " -LogBaseName "comprehensive_audit" -Raw
    Write-SecurityLog -Message "[6] RDP CONNECTIONS (Last $RDPDays days):" -Level 'Warning' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    
    $rdpConnections = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4624
        StartTime=(Get-Date).AddDays(-$RDPDays)
    } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue |
        Where-Object {$_.Properties[8].Value -eq 10} |
        Select-Object TimeCreated, 
                      @{N='Account';E={$_.Properties[5].Value}}, 
                      @{N='SourceIP';E={$_.Properties[18].Value}},
                      @{N='LogonID';E={$_.Properties[7].Value}}

    if ($rdpConnections) {
        $rdpConnections | Write-SecurityLogTable -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        
        if ($ExportCSV) {
            $rdpConnections | Export-Csv -Path "$csvPath\rdp_connections_$csvTimestamp.csv" -NoTypeInformation
            Write-SecurityLog -Message "Exported to: $csvPath\rdp_connections_$csvTimestamp.csv" -Level 'Info' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
        }
    } else {
        Write-SecurityLog -Message "No RDP connections found." -Level 'Success' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    }

    Write-SecurityLog -Message " " -LogBaseName "comprehensive_audit" -Raw
    Write-SecurityLog -Message "Review any findings above carefully." -Level 'Warning' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput

    # Complete audit log
    Complete-SecurityAuditLog -LogBaseName "comprehensive_audit" -AuditType "Windows Security Audit Log Check"
    
    # Display log location
    $logPath = Join-Path $PSScriptRoot $LogDirectory
    $logFile = "comprehensive_audit_$(Get-Date -Format 'yyyy-MM-dd').log"
    $fullLogPath = Join-Path $logPath $logFile
    Write-Host "`nLog file saved to: $fullLogPath" -ForegroundColor Green
    
    if ($ExportCSV) {
        Write-Host "CSV exports saved to: $csvPath" -ForegroundColor Green
    }
    
    # Run Claude analysis if available and not skipped
    if (-not $SkipClaudeAnalysis) {
        Invoke-ClaudeAnalysis -LogFile $fullLogPath -AuditType "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    }

} catch {
    Write-SecurityLog -Message "ERROR: $($_.Exception.Message)" -Level 'Error' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    Write-SecurityLog -Message "Stack trace: $($_.ScriptStackTrace)" -Level 'Error' -LogBaseName "comprehensive_audit" -NoConsoleOutput:$NoConsoleOutput
    exit 1
}