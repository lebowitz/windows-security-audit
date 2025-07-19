# Windows Security Audit Tools

A collection of PowerShell scripts for detecting Indicators of Compromise (IOCs) on Windows systems. These tools help security professionals and system administrators quickly assess potential security threats.

## 🔍 Overview

This repository contains PowerShell scripts that check for common signs of compromise including:
- Failed login attempts
- Suspicious PowerShell activity
- Unusual service installations
- Active network connections
- Recently created scheduled tasks
- Suspicious startup items

## 🚀 Quick Start

```powershell
# Run the quick security check
.\quick_security_check.ps1

# Run comprehensive audit (requires admin privileges)
.\comprehensive_audit.ps1

# View help and available parameters
.\quick_security_check.ps1 -Help
.\comprehensive_audit.ps1 -Help
```

## 🤖 AI-Powered Analysis with Claude Code

Both scripts now feature automatic AI analysis when [Claude Code](https://claude.ai/code) is installed on your system (either in Windows or WSL). After completing the security scan, Claude analyzes the results and provides:

- **Risk Assessment**: Critical/High/Medium/Low rating
- **Security Summary**: Concise overview of findings
- **Top Concerns**: Prioritized list of security issues
- **Recommended Actions**: Immediate steps to take
- **Pattern Detection**: Identifies trends and anomalies

### Example Claude Analysis Output

```
[2025-07-19 10:46:38] [Warning] === CLAUDE SECURITY ANALYSIS ===
## Security Analysis Summary
**Brief Summary:** The audit detected 3 failed login attempts, extensive PowerShell 
scriptblock logging activity (false positive), and multiple kernel driver installations 
from MSI Center and AMD software. No RDP connections or suspicious process creation 
were found.
**Risk Assessment:** **LOW-MEDIUM**

## Top Security Concerns
1. **Failed Login Attempts** - 3 failed login attempts detected with failure reason 
   %%2313 (unknown username or bad password)
2. **Kernel Driver Installations** - Multiple kernel-mode drivers installed by MSI 
   Center and AMD Tools, which have low-level system access
3. **Repetitive Service Installations** - Same drivers being installed multiple times 
   on different dates (July 12, 14, 18)

## Recommended Immediate Actions
1. **Investigate Failed Logins:** Check if these were legitimate login attempts or 
   potential unauthorized access attempts
2. **Verify MSI Center/AMD Drivers:** Confirm these are legitimate installations 
   from your hardware management software
3. **PowerShell Logging:** The extensive PowerShell alerts appear to be false 
   positives from legitimate NetAdapter module loading - consider tuning detection rules

## Patterns Detected
- **False Positive Pattern:** All PowerShell alerts are from legitimate Windows 
  NetAdapter module scriptblock creation
- **Service Pattern:** MSI Center appears to be reinstalling the same drivers 
  repeatedly, suggesting possible software issues or updates
- No actual malicious activity detected - all findings appear to be legitimate 
  system activity
[2025-07-19 10:46:38] [Warning] === END CLAUDE ANALYSIS ===
```

### Disabling AI Analysis

If you prefer to run the scripts without AI analysis:

```powershell
# Skip Claude analysis
.\comprehensive_audit.ps1 -SkipClaudeAnalysis
```

## 📊 Sample Output (Redacted)

Below is redacted output from a real system scan showing what the tools detect:

### Quick Security Scan

```
=== QUICK SECURITY SCAN ===

[1] Recent Remote Logins (RDP/SSH):
(No suspicious logins detected)

[2] Suspicious Processes Running:

ProcessName    Id StartTime             Path                                           
-----------    -- ---------             ----                                           
cmd         2xxxx 7/18/2025 6:30:43 PM  C:\WINDOWS\system32\cmd.exe                    
powershell  8xxxx 7/19/2025 10:13:25 AM C:\WINDOWS\System32\WindowsPowerShell\v1.0\... 

[3] Active Network Connections (External):

LocalPort RemoteAddress    RemotePort OwningProcess ProcessName
--------- -------------    ---------- ------------- -----------
    63xxx 54.xxx.xx.111           443         20xxx Slack      
    63xxx 34.xxx.xx.10            443         20xxx Slack      
    63xxx 162.xxx.xxx.229         443         26xxx chrome     
    63xxx 142.xxx.xxx.188        5228         26xxx chrome     

[4] Recently Created Scheduled Tasks:
(Showing only recently modified tasks)

[5] Suspicious Startup Items:
(No suspicious startup items detected)

=== SCAN COMPLETE ===
```

### Comprehensive Audit Log Analysis

```
=== WINDOWS SECURITY AUDIT LOG CHECK ===
Checking for potential Indicators of Compromise (IOCs)...

[1] FAILED LOGIN ATTEMPTS (Last 24 hours):
No failed login attempts found.

[2] NEW USER ACCOUNTS (Last 7 days):
No new user accounts created.

[3] POWERSHELL ACTIVITY:
Suspicious PowerShell commands detected:
(Note: Many false positives from legitimate system scripts)

TimeCreated        : 7/19/2025 10:07:05 AM
Suspicious Command : Creating Scriptblock text (legitimate system activity)

[4] NEW SERVICE INSTALLATIONS (Last 7 days):
No new services installed.

[5] SUSPICIOUS PROCESS CREATION (Last 24 hours):
(Showing cmd.exe and powershell.exe executions for security monitoring)

[6] RDP CONNECTIONS (Last 7 days):
No RDP connections found.

=== SCAN COMPLETE ===
```

## 📁 Logging and Output

All scripts create daily rolling logs in the `logs/` subdirectory:
- `quick_security_check_YYYY-MM-DD.log`
- `comprehensive_audit_YYYY-MM-DD.log`

Key features:
- **Daily rotation**: New log file each day
- **Timestamped entries**: All events logged with precise timestamps
- **Severity levels**: Info, Warning, Error, Success, Alert
- **Console + File output**: See results in real-time and review later
- **Custom log directory**: Use `-LogDirectory` parameter

## 🛡️ Security Checks Performed

### 1. **Login Monitoring**
- Checks Event ID 4625 (Failed logins)
- Checks Event ID 4624 (Successful logins, especially Type 10 for RDP)
- Monitors for brute force attempts

### 2. **PowerShell Activity**
- Scans Event ID 4104 (PowerShell script block logging)
- Looks for keywords: `download`, `invoke-expression`, `encodedcommand`, `hidden`, `bypass`
- Helps detect fileless malware and living-off-the-land techniques

### 3. **Service Monitoring**
- Checks Event ID 7045 (New service installations)
- Critical for detecting persistence mechanisms

### 4. **Network Connections**
- Lists all established connections to external IPs
- Filters out local/private IP ranges
- Shows process names for each connection

### 5. **Scheduled Tasks**
- Reviews recently created scheduled tasks
- Common persistence method for malware

### 6. **Process Creation**
- Monitors Event ID 4688 (Process creation)
- Focuses on commonly abused executables

## 📋 Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- Administrator privileges (for full audit capabilities)
- Audit policies enabled for comprehensive logging
- [Claude Code](https://claude.ai/code) (optional, for AI analysis)

## 📝 Command Line Parameters

### Quick Security Check
```powershell
.\quick_security_check.ps1 [-LogDirectory <string>] [-NoConsoleOutput] 
                           [-ShowAllProcesses] [-ShowAllConnections]
                           [-DaysBack <int>] [-SkipClaudeAnalysis] [-Help]
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-LogDirectory` | Custom log directory path | `logs` |
| `-NoConsoleOutput` | Suppress console output (log only) | `$false` |
| `-ShowAllProcesses` | Show all processes, not just suspicious | `$false` |
| `-ShowAllConnections` | Show all connections, not just external | `$false` |
| `-DaysBack` | Days to look back for scheduled tasks | `7` |
| `-SkipClaudeAnalysis` | Skip AI analysis | `$false` |
| `-Help` | Show detailed help | - |

### Comprehensive Audit
```powershell
.\comprehensive_audit.ps1 [-LogDirectory <string>] [-NoConsoleOutput]
                         [-FailedLoginHours <int>] [-NewUserDays <int>]
                         [-ServiceDays <int>] [-ProcessHours <int>]
                         [-RDPDays <int>] [-MaxEvents <int>]
                         [-SkipPowerShell] [-ExportCSV]
                         [-SkipClaudeAnalysis] [-Help]
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-LogDirectory` | Custom log directory path | `logs` |
| `-NoConsoleOutput` | Suppress console output (log only) | `$false` |
| `-FailedLoginHours` | Hours to check for failed logins | `24` |
| `-NewUserDays` | Days to check for new users | `7` |
| `-ServiceDays` | Days to check for new services | `7` |
| `-ProcessHours` | Hours to check for suspicious processes | `24` |
| `-RDPDays` | Days to check for RDP connections | `7` |
| `-MaxEvents` | Max events per category (performance) | `1000` |
| `-SkipPowerShell` | Skip PowerShell activity analysis | `$false` |
| `-ExportCSV` | Export findings to CSV files | `$false` |
| `-SkipClaudeAnalysis` | Skip AI analysis | `$false` |
| `-Help` | Show detailed help | - |

## 🔧 Configuration

### Enable PowerShell Script Block Logging
```powershell
# Run as Administrator
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

### Enable Process Creation Auditing
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

## ⚠️ Important Notes

1. **False Positives**: PowerShell logging often captures legitimate system scripts
2. **Performance**: These scripts may take time on systems with large event logs
3. **Privileges**: Some checks require administrative rights
4. **Privacy**: Always redact sensitive information when sharing output

## 🤝 Contributing

Feel free to submit issues and enhancement requests!

## 📜 License

Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) - See LICENSE file for details

This means:
- ✅ **Free to use** for personal and non-commercial purposes
- ✅ **Share and adapt** the code as needed
- ❌ **No commercial use** without permission
- 📝 **Attribution required** when sharing

## 🔒 Disclaimer

These tools are for defensive security purposes only. Always ensure you have proper authorization before running security audits on any system.