# Windows Security Audit Log Check for IOCs
# Run as Administrator for full access

Write-Host "=== WINDOWS SECURITY AUDIT LOG CHECK ===" -ForegroundColor Cyan
Write-Host "Checking for potential Indicators of Compromise (IOCs)..." -ForegroundColor Yellow

# 1. Check failed login attempts
Write-Host "`n[1] FAILED LOGIN ATTEMPTS (Last 24 hours):" -ForegroundColor Yellow
$failedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | 
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='Source';E={$_.Properties[19].Value}}

if ($failedLogins) {
    $failedLogins | Format-Table -AutoSize
} else {
    Write-Host "No failed login attempts found." -ForegroundColor Green
}

# 2. Check for new user accounts
Write-Host "`n[2] NEW USER ACCOUNTS (Last 7 days):" -ForegroundColor Yellow
$newUsers = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{N='NewAccount';E={$_.Properties[0].Value}}, @{N='CreatedBy';E={$_.Properties[4].Value}}

if ($newUsers) {
    $newUsers | Format-Table -AutoSize
} else {
    Write-Host "No new user accounts created." -ForegroundColor Green
}

# 3. Check for suspicious PowerShell activity
Write-Host "`n[3] POWERSHELL ACTIVITY:" -ForegroundColor Yellow
$psEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
    Where-Object {$_.Message -match 'download|invoke-expression|encodedcommand|hidden|bypass'} |
    Select-Object TimeCreated, @{N='Suspicious Command';E={($_.Message -split "`n")[0..1] -join " "}}

if ($psEvents) {
    Write-Host "Suspicious PowerShell commands detected:" -ForegroundColor Red
    $psEvents | Format-List
} else {
    Write-Host "No suspicious PowerShell activity found." -ForegroundColor Green
}

# 4. Check for service installations
Write-Host "`n[4] NEW SERVICE INSTALLATIONS (Last 7 days):" -ForegroundColor Yellow
$newServices = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}}, @{N='ServiceFile';E={$_.Properties[1].Value}}

if ($newServices) {
    $newServices | Format-Table -AutoSize
} else {
    Write-Host "No new services installed." -ForegroundColor Green
}

# 5. Check for unusual process creation
Write-Host "`n[5] SUSPICIOUS PROCESS CREATION (Last 24 hours):" -ForegroundColor Yellow
$suspiciousProcs = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
    Where-Object {$_.Message -match 'cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe'} |
    Select-Object TimeCreated, @{N='Process';E={$_.Properties[5].Value}} -First 20

if ($suspiciousProcs) {
    $suspiciousProcs | Format-Table -AutoSize
} else {
    Write-Host "No suspicious process creation found." -ForegroundColor Green
}

# 6. Check for RDP connections
Write-Host "`n[6] RDP CONNECTIONS (Last 7 days):" -ForegroundColor Yellow
$rdpConnections = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
    Where-Object {$_.Properties[8].Value -eq 10} |
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}

if ($rdpConnections) {
    $rdpConnections | Format-Table -AutoSize
} else {
    Write-Host "No RDP connections found." -ForegroundColor Green
}

Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor Cyan
Write-Host "Review any findings above carefully." -ForegroundColor Yellow