$outputFile = "R_ps.txt"

# List running services
$services = Get-WmiObject Win32_Service | Select-Object DisplayName, StartMode, State, StartName
"Running Services:" | Out-File $outputFile
$services | Format-Table | Out-File $outputFile -Append

# Identify processes with high privileges
$highPrivProcesses = Get-Process | Where-Object {$_.ProcessName -ne "Idle"} | 
    Sort-Object -Property WorkingSet64 -Descending | 
    Select-Object -First 10 ProcessName, Id, WorkingSet64, Path

"`nTop 10 Processes by Memory Usage:" | Out-File $outputFile -Append
$highPrivProcesses | Format-Table | Out-File $outputFile -Append

Write-Host "Service and Process audit completed. Results saved in $outputFile"