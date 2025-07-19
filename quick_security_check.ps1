# Quick Security Check
Write-Host "=== QUICK SECURITY SCAN ===" -ForegroundColor Cyan

# 1. Check for recent RDP logins
Write-Host "`n[1] Recent Remote Logins (RDP/SSH):" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object {$_.Message -match 'Logon Type:\s+(10|3)'} |
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[8].Value}} -First 5 |
    Format-Table -AutoSize

# 2. Check running suspicious processes
Write-Host "`n[2] Suspicious Processes Running:" -ForegroundColor Yellow
Get-Process | Where-Object {$_.ProcessName -match 'nc|ncat|netcat|mimikatz|psexec|wmic|powershell|cmd'} |
    Select-Object ProcessName, Id, StartTime, Path | Format-Table -AutoSize

# 3. Check network connections
Write-Host "`n[3] Active Network Connections (External):" -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notmatch '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' -and $_.RemoteAddress -ne '::1'} |
    Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess, @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    Format-Table -AutoSize

# 4. Check scheduled tasks created recently
Write-Host "`n[4] Recently Created Scheduled Tasks:" -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {$_.Date -gt (Get-Date).AddDays(-7)} |
    Select-Object TaskName, Author, Date | Format-Table -AutoSize

# 5. Check startup programs
Write-Host "`n[5] Suspicious Startup Items:" -ForegroundColor Yellow
Get-CimInstance Win32_StartupCommand | 
    Where-Object {$_.Command -match 'powershell|cmd|wscript|cscript|mshta'} |
    Select-Object Name, Command, Location | Format-Table -AutoSize

Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor Cyan