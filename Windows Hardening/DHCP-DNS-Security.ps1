reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v "TcpReceivePacketSize" /t REG_DWORD /d 0xFF00 /f
net stop DNS
net start DNS
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name MaximumUdpPacketSize -Type DWord -Value 0x4C5 -Force
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v MaximumUdpPacketSize /t REG_DWORD /d 0x4C5 /f

Set-DnsServerRRL -Mode Enable -Force
Set-DnsServerResponseRateLimiting -ResetToDefault -Force
Set-DnsServerDiagnostics -EnableLoggingForPluginDllEvent $true
Set-DhcpServerv4DnsSetting -NameProtection $True
Set-DhcpServerv4DnsSetting -DisableDnsPtrRRUpdate 1
Set-DhcpServerv4DnsSetting -DynamicUpdates "Never" -DeleteDnsRRonLeaseExpiry $True
Set-DhcpServerv4DnsSetting -UpdateDnsRRForOlderClients $False
Set-mppreference -DisableDnsOverTcpParsing $False
Set-mppreference -DisableDnsParsing $False
Set-mppreference -EnableDnsSinkhole $True
Set-DnsServerRecursion -Enable $false
Set-DnsServerRecursion -SecureResponse $true

net stop DNS
net start DNS
dnscmd /config /enablednssec 1
dnscmd /config /retrieveroottrustanchors
dnscmd /config /addressanswerlimit 5
dnscmd /config /bindsecondaries 0
dnscmd /config /bootmethod 3
dnscmd /config /defaultagingstate 1
dnscmd /config /defaultnorefreshinterval 0xA8
dnscmd /config /defaultrefreshinterval  0xA8
dnscmd /config /disableautoreversezones  1
dnscmd /config /disablensrecordsautocreation 1
dnscmd /config /dspollinginterval 30
dnscmd /config /dstombstoneinterval 30
dnscmd /config /ednscachetimeout  604,800
dnscmd /config /enableglobalnamessupport 0
dnscmd /config /enableglobalqueryblocklist 1
dnscmd /config /globalqueryblocklist isatap wpad
dnscmd /config /eventloglevel 4
dnscmd /config /forwarddelegations 1
dnscmd /config /forwardingtimeout 0x5
dnscmd /config /globalneamesqueryorder 1
dnscmd /config /EnableVersionQuery 0
dnscmd /config /isslave 0
dnscmd /config /localnetpriority 0
dnscmd /config /logfilemaxsize 0xFFFFFFFF
# dp later dnscmd /config /logfilepath  
dnscmd /config /logipfilterlist 
dnscmd /config /loglevel 0xFFFF
dnscmd /config /maxcachesize 10000
dnscmd /config /maxcachettl 0x15180
dnscmd /config /maxnegativecachettl 0x384
dnscmd /config /namecheckflag 2
dnscmd /config /norecursion 0
dnscmd /config /recursionretry  0x3
dnscmd /config /AllowUpdate 2
dnscmd /config /recursionretry  0xF
dnscmd /config /roundrobin  1  
# dnscmd /config /rpcprotocol 0x2 
dnscmd /config /scavenginginterval 0x0
dnscmd /config /secureresponses 0
dnscmd /config /sendport 0x0
dnscmd /config /strictfileparsing  1
dnscmd /config /updateoptions 0x30F  
dnscmd /config /writeauthorityns  0
dnscmd /config /xfrconnecttimeout    0x1E
dnscmd /config /allowupdate 2
dnscmd /config /enableednsprobes 0
dnscmd /config /localnetprioritynetmask 0x0000ffff
dnscmd /config /openaclonproxyupdates 0
Dnscmd /config /DisableNSRecordsAutoCreation 1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v TcpReceivePacketSize /t REG_DWORD /d 0xFF00 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v MaximumUdpPacketSize /t REG_DWORD /d 0x4C5 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] CVE-2020-1350 and CVE-2020-25705 mitigations in place" -ForegroundColor white
dnscmd /config /enableglobalqueryblocklist 1 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled global query block list for DNS" -ForegroundColor white
Set-DnsServerRRL -Mode Enable -Force | Out-Null
Set-DnsServerResponseRateLimiting -ResetToDefault -Force | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Response rate limiting enabled" -ForegroundColor white
net stop DNS
net start DNS
