# DC detection
$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
}

# IIS detection
$IIS = $false
if (Get-Service -Name W3SVC 2>$null) {
    $IIS = $true
}
