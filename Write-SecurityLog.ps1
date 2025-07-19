# Security Audit Logging Module
# Provides daily rolling log functionality for security audit scripts

function Write-SecurityLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Alert')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory=$false)]
        [string]$LogBaseName = 'security_audit',
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsoleOutput,
        
        [Parameter(Mandatory=$false)]
        [switch]$Raw
    )
    
    # Define log directory
    $LogDirectory = Join-Path $PSScriptRoot "logs"
    
    # Create log directory if it doesn't exist
    if (!(Test-Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    
    # Generate daily log filename
    $DateString = Get-Date -Format "yyyy-MM-dd"
    $LogFileName = "${LogBaseName}_${DateString}.log"
    $LogPath = Join-Path $LogDirectory $LogFileName
    
    # Format timestamp
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Format the log entry
    if ($Raw) {
        $LogEntry = $Message
    } else {
        $LogEntry = "[$Timestamp] [$Level] $Message"
    }
    
    # Write to log file
    $LogEntry | Out-File -FilePath $LogPath -Append -Encoding UTF8
    
    # Write to console if not suppressed
    if (!$NoConsoleOutput) {
        switch ($Level) {
            'Error' { Write-Host $LogEntry -ForegroundColor Red }
            'Warning' { Write-Host $LogEntry -ForegroundColor Yellow }
            'Success' { Write-Host $LogEntry -ForegroundColor Green }
            'Alert' { Write-Host $LogEntry -ForegroundColor Magenta }
            default { Write-Host $LogEntry }
        }
    }
}

function Write-SecurityLogTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [object]$InputObject,
        
        [Parameter(Mandatory=$false)]
        [string]$LogBaseName = 'security_audit',
        
        [Parameter(Mandatory=$false)]
        [string]$Title = "",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsoleOutput
    )
    
    Begin {
        $objects = @()
        if ($Title) {
            Write-SecurityLog -Message $Title -Level 'Info' -LogBaseName $LogBaseName -NoConsoleOutput:$NoConsoleOutput
            $separator = "-" * 80
            Write-SecurityLog -Message $separator -LogBaseName $LogBaseName -NoConsoleOutput:$NoConsoleOutput -Raw
        }
    }
    
    Process {
        $objects += $InputObject
    }
    
    End {
        if ($objects.Count -eq 0) {
            Write-SecurityLog -Message "No data to display" -LogBaseName $LogBaseName -NoConsoleOutput:$NoConsoleOutput
            return
        }
        
        # Convert to table format for logging
        $tableOutput = $objects | Format-Table -AutoSize | Out-String
        
        # Write table to log
        $tableOutput -split "`n" | ForEach-Object {
            if ($_.Trim()) {
                Write-SecurityLog -Message $_ -LogBaseName $LogBaseName -NoConsoleOutput -Raw
            }
        }
        
        # Display on console if not suppressed
        if (!$NoConsoleOutput) {
            $objects | Format-Table -AutoSize
        }
    }
}

function Write-SecurityLogList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [object]$InputObject,
        
        [Parameter(Mandatory=$false)]
        [string]$LogBaseName = 'security_audit',
        
        [Parameter(Mandatory=$false)]
        [string]$Title = "",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsoleOutput
    )
    
    Begin {
        $objects = @()
        if ($Title) {
            Write-SecurityLog -Message $Title -Level 'Info' -LogBaseName $LogBaseName -NoConsoleOutput:$NoConsoleOutput
            $separator = "-" * 80
            Write-SecurityLog -Message $separator -LogBaseName $LogBaseName -NoConsoleOutput:$NoConsoleOutput -Raw
        }
    }
    
    Process {
        $objects += $InputObject
    }
    
    End {
        if ($objects.Count -eq 0) {
            Write-SecurityLog -Message "No data to display" -LogBaseName $LogBaseName -NoConsoleOutput:$NoConsoleOutput
            return
        }
        
        # Convert to list format for logging
        $listOutput = $objects | Format-List | Out-String
        
        # Write list to log
        $listOutput -split "`n" | ForEach-Object {
            if ($_.Trim()) {
                Write-SecurityLog -Message $_ -LogBaseName $LogBaseName -NoConsoleOutput -Raw
            }
        }
        
        # Display on console if not suppressed
        if (!$NoConsoleOutput) {
            $objects | Format-List
        }
    }
}

function Start-SecurityAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$LogBaseName = 'security_audit',
        
        [Parameter(Mandatory=$false)]
        [string]$AuditType = 'Security Audit'
    )
    
    $separator = "=" * 80
    Write-SecurityLog -Message $separator -LogBaseName $LogBaseName -Raw
    Write-SecurityLog -Message "$AuditType Started" -Level 'Info' -LogBaseName $LogBaseName
    Write-SecurityLog -Message "Computer: $env:COMPUTERNAME" -LogBaseName $LogBaseName
    Write-SecurityLog -Message "User: $env:USERNAME" -LogBaseName $LogBaseName
    Write-SecurityLog -Message $separator -LogBaseName $LogBaseName -Raw
    Write-SecurityLog -Message " " -LogBaseName $LogBaseName -Raw
}

function Complete-SecurityAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$LogBaseName = 'security_audit',
        
        [Parameter(Mandatory=$false)]
        [string]$AuditType = 'Security Audit'
    )
    
    $separator = "=" * 80
    Write-SecurityLog -Message " " -LogBaseName $LogBaseName -Raw
    Write-SecurityLog -Message $separator -LogBaseName $LogBaseName -Raw
    Write-SecurityLog -Message "$AuditType Completed" -Level 'Success' -LogBaseName $LogBaseName
    Write-SecurityLog -Message $separator -LogBaseName $LogBaseName -Raw
}

function Invoke-ClaudeAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogFile,
        
        [Parameter(Mandatory=$true)]
        [string]$AuditType,
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsoleOutput
    )
    
    # Check if Claude Code is available - first in Windows, then in WSL
    $claudeCode = Get-Command "claude" -ErrorAction SilentlyContinue
    $claudeCommand = "claude"
    $useWSL = $false
    
    if (-not $claudeCode) {
        # Check if WSL is available
        $wslExists = Get-Command "wsl" -ErrorAction SilentlyContinue
        
        if ($wslExists) {
            # Check if claude exists in WSL
            $wslClaudeCheck = & wsl which claude 2>$null
            if ($wslClaudeCheck) {
                $claudeCommand = "wsl claude"
                $useWSL = $true
                Write-SecurityLog -Message "Claude Code found in WSL" -Level 'Info' -LogBaseName $AuditType -NoConsoleOutput:$NoConsoleOutput
            }
        }
    }
    
    if (-not $claudeCode -and -not $useWSL) {
        Write-SecurityLog -Message "Claude Code not found on system (checked Windows and WSL). Skipping AI analysis." -Level 'Info' -LogBaseName $AuditType -NoConsoleOutput:$NoConsoleOutput
        return $false
    }
    
    Write-SecurityLog -Message " " -LogBaseName $AuditType -Raw
    Write-SecurityLog -Message "Analyzing results with Claude Code..." -Level 'Info' -LogBaseName $AuditType -NoConsoleOutput:$NoConsoleOutput
    
    try {
        # Prepare the analysis prompt
        $prompt = @"
You are a security analyst reviewing Windows security audit results. Please analyze the following security audit log and provide:

1. A brief summary of the findings (2-3 sentences)
2. Risk assessment (Critical/High/Medium/Low)
3. Top 3-5 security concerns found (if any)
4. Recommended immediate actions (if needed)
5. Any patterns or anomalies detected

Keep your analysis concise and actionable. Focus on actual security issues, not routine activity.

Audit Type: $AuditType
Log File Contents:
"@
        
        # Read the log file content
        $logContent = Get-Content -Path $LogFile -Raw
        
        # Create a temporary file with the prompt and log content
        $tempFile = [System.IO.Path]::GetTempFileName()
        $fullPrompt = $prompt + "`n`n" + $logContent
        Set-Content -Path $tempFile -Value $fullPrompt -Encoding UTF8
        
        # Run Claude analysis
        Write-SecurityLog -Message "Running Claude analysis..." -Level 'Info' -LogBaseName $AuditType -NoConsoleOutput:$NoConsoleOutput
        
        # Execute claude with the prompt
        if ($useWSL) {
            # Convert Windows path to WSL path - need to escape backslashes
            $escapedPath = $tempFile -replace '\\', '\\\\'
            $wslTempFile = & wsl wslpath -u "$escapedPath"
            
            # Use stdin redirection for WSL
            $analysisOutput = Get-Content -Path $tempFile -Raw | & wsl claude 2>&1
        } else {
            $analysisOutput = & claude -c "$fullPrompt" 2>&1
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-SecurityLog -Message " " -LogBaseName $AuditType -Raw
            Write-SecurityLog -Message "=== CLAUDE SECURITY ANALYSIS ===" -Level 'Warning' -LogBaseName $AuditType -NoConsoleOutput:$NoConsoleOutput
            
            # Log the analysis output
            $analysisOutput -split "`n" | ForEach-Object {
                if ($_.Trim()) {
                    Write-SecurityLog -Message $_ -LogBaseName $AuditType -NoConsoleOutput:$NoConsoleOutput -Raw
                }
            }
            
            Write-SecurityLog -Message "=== END CLAUDE ANALYSIS ===" -Level 'Warning' -LogBaseName $AuditType -NoConsoleOutput:$NoConsoleOutput
            Write-SecurityLog -Message " " -LogBaseName $AuditType -Raw
        } else {
            Write-SecurityLog -Message "Claude analysis failed: $analysisOutput" -Level 'Error' -LogBaseName $AuditType -NoConsoleOutput:$NoConsoleOutput
        }
        
        # Clean up temp file
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        
        return $true
        
    } catch {
        Write-SecurityLog -Message "Error during Claude analysis: $($_.Exception.Message)" -Level 'Error' -LogBaseName $AuditType -NoConsoleOutput:$NoConsoleOutput
        return $false
    }
}

# Export functions
Export-ModuleMember -Function Write-SecurityLog, Write-SecurityLogTable, Write-SecurityLogList, Start-SecurityAuditLog, Complete-SecurityAuditLog, Invoke-ClaudeAnalysis