$outputFile = "R_network.txt"

# Network interface configuration
$networkConfig = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway
"Network Interfaces:" | Out-File $outputFile
$networkConfig | Format-Table | Out-File $outputFile -Append

# Firewall rules
$firewallRules = Get-NetFirewallRule | Where-Object Enabled -eq 'True' | Select-Object DisplayName, Direction, Action, Profile
"`nEnabled Firewall Rules:" | Out-File $outputFile -Append
$firewallRules | Format-Table | Out-File $outputFile -Append

# Open ports
$openPorts = Get-NetTCPConnection | Where-Object State -eq 'Listen' | Select-Object LocalAddress, LocalPort, OwningProcess
"`nOpen Ports:" | Out-File $outputFile -Append
$openPorts | Format-Table | Out-File $outputFile -Append

Write-Host "Network configuration audit completed. Results saved in $outputFile"
