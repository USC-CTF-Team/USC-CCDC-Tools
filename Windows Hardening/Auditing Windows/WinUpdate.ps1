$outputFile = "R_winupdate.txt"

# Check for missing security updates
$missingUpdates = Get-WmiObject -Class Win32_QuickFixEngineering | 
    Where-Object {$_.InstalledOn -lt (Get-Date).AddDays(-30)} | 
    Select-Object HotFixID, Description, InstalledOn

"Missing Updates (>30 days old):" | Out-File $outputFile
$missingUpdates | Format-Table | Out-File $outputFile -Append

# Verify Windows Update settings
$updateSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" | 
    Select-Object AUOptions, ScheduledInstallDay, ScheduledInstallTime

"`nWindows Update Settings:" | Out-File $outputFile -Append
$updateSettings | Format-Table | Out-File $outputFile -Append

Write-Host "Windows Update audit completed. Results saved in $outputFile"