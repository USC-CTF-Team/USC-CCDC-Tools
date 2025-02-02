Get-ChildItem -Path . -Filter *.ps1 | ForEach-Object {
    Write-Host "Running $($_.Name)..." -ForegroundColor Cyan
    & $_.FullName
    Write-Host "Completed $($_.Name)" -ForegroundColor Green
    Write-Host ""
}