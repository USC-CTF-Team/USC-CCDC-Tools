$outputFile = "R_installed.txt"

# List installed software
$installedSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor
"Installed Software:" | Out-File $outputFile
$installedSoftware | Format-Table | Out-File $outputFile -Append

Write-Host "Software inventory completed. Results saved in $outputFile"