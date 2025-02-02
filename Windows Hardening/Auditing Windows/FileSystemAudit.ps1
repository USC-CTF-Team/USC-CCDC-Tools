$outputFile = "R_fs.txt"

# Scan for files with sensitive permissions
$sensitiveFiles = Get-ChildItem C:\ -Recurse -Force -ErrorAction SilentlyContinue | 
    Where-Object {$_.FullName -match "password|confidential|secret" -and !$_.PSIsContainer} | 
    Select-Object FullName, LastWriteTime

"Potentially Sensitive Files:" | Out-File $outputFile
$sensitiveFiles | Format-Table | Out-File $outputFile -Append

# Identify large files
$largeFiles = Get-ChildItem C:\ -Recurse -Force -ErrorAction SilentlyContinue | 
    Where-Object {!$_.PSIsContainer -and $_.Length -gt 100MB} | 
    Select-Object FullName, Length, LastWriteTime

"`nLarge Files (>100MB):" | Out-File $outputFile -Append
$largeFiles | Format-Table | Out-File $outputFile -Append

Write-Host "File System audit completed. Results saved in $outputFile"