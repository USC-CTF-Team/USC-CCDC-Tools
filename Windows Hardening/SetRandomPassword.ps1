Write-Host "Changing local passwords..." -ForegroundColor Gray

New-Item -Path "user_list.txt" -ItemType File -Force | Out-Null

try {
    $userList = @()
    $users = Get-LocalUser
    foreach ($user in $users) {
        $newPassword = -join ((33..126) | Get-Random -Count 16 | Foreach-Object {[char]$_})
        $user | Set-LocalUser -Password (ConvertTo-SecureString -AsPlainText $newPassword -Force)
        $user | Set-LocalUser -PasswordNeverExpires $false -UserMayChangePassword $true 
        touch user_list.txt
        "$($user),$newPassword" | Out-File -FilePath "user_list.txt" -Append
    }

}
catch {
    Write-Output "$Error[0] $_"
}
Write-Warning "Disabling Guest account"
Get-LocalUser Guest | Disable-LocalUser

Write-Host "Please enter a new password for the Administrator account:" -ForegroundColor Yellow
$adminPassword = Read-Host -AsSecureString

# Convert SecureString to plain text for file writing
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPassword)
$adminPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Change Administrator password
Get-LocalUser Administrator | Set-LocalUser -Password $adminPassword
Get-LocalUser Administrator | Set-LocalUser -PasswordNeverExpires $false -UserMayChangePassword $true

"Administrator,$adminPasswordPlain" | Out-File -FilePath "user_list.txt" -Append

Write-Host "End of Execution" -ForegroundColor Green
