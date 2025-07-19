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

MIT License - See LICENSE file for details

## 🔒 Disclaimer

These tools are for defensive security purposes only. Always ensure you have proper authorization before running security audits on any system.