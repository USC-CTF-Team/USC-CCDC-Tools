$outputFile = "R_reg.txt"

# Scan for autorun entries
$autorunEntries = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
"Autorun Entries:" | Out-File $outputFile
$autorunEntries | Format-Table -AutoSize | Out-File $outputFile -Append

# Identify recently modified registry keys
$recentlyModifiedKeys = Get-ChildItem "HKLM:\SOFTWARE" -Recurse -ErrorAction SilentlyContinue | 
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | 
    Select-Object Name, LastWriteTime

"`nRecently Modified Registry Keys:" | Out-File $outputFile -Append
$recentlyModifiedKeys | Format-Table | Out-File $outputFile -Append

Write-Host "Registry audit completed. Results saved in $outputFile"
