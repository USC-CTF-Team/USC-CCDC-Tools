$outputFile = "R_usrgrp.txt"

# Enumerate local users
$users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet
"Local Users:" | Out-File $outputFile
$users | Format-Table | Out-File $outputFile -Append

# Enumerate local groups
$groups = Get-LocalGroup | Select-Object Name, Description
"`nLocal Groups:" | Out-File $outputFile -Append
$groups | Format-Table | Out-File $outputFile -Append

# Identify users with administrative privileges
$adminUsers = Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource
"`nUsers in Administrators group:" | Out-File $outputFile -Append
$adminUsers | Format-Table | Out-File $outputFile -Append

Write-Host "User and Group enumeration completed. Results saved in $outputFile"
