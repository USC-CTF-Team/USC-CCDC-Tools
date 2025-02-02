# Ensure WebAdministration and IISAdministration modules are imported
Import-Module WebAdministration
Import-Module IISAdministration

# Check if the Web-Server feature is installed
if ((Get-WindowsFeature Web-Server).InstallState -eq "Installed") {
    # Set application pool identity type to LocalSystem (4) for all app pools
    Foreach ($item in (Get-ChildItem IIS:\AppPools)) {
        $tempPath = "IIS:\AppPools\" + $item.name
        Set-ItemProperty -Path $tempPath -Name processModel.identityType -Value 4
    }

    # Disable directory browsing for all sites
    Foreach ($item in (Get-ChildItem IIS:\Sites)) {
        $tempPath = "IIS:\Sites\" + $item.name
        Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath $tempPath -Value False
    }

    # Allow PowerShell to modify anonymousAuthentication settings
    Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -Metadata overrideMode -Value Allow -PSPath IIS:/

    # Disable anonymous authentication for all sites
    Foreach ($item in (Get-ChildItem IIS:\Sites)) {
        $tempPath = "IIS:\Sites\" + $item.name
        Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication $tempPath -Value 0
    }

    # Deny PowerShell the ability to modify anonymousAuthentication settings
    Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -Metadata overrideMode -Value Deny -PSPath IIS:/

    # Delete custom error pages
    $sysDrive = $Env:Path.Substring(0, 3)
    $tempPath = (Get-WebConfiguration "//httperrors/error").prefixLanguageFilePath | Select-Object -First 1
    $sysDrive += $tempPath.Substring($tempPath.IndexOf('\') + 1)
    Get-ChildItem -Path $sysDrive -Include *.* -File -Recurse | ForEach-Object { $_.Delete() }
}

# Set various web application and site security settings
# Ensure forms authentication requires SSL
Add-WebConfigurationProperty -Filter "/system.webServer/security/authentication/forms" -Name "requireSSL" -Value $true

# Ensure forms authentication is set to use cookies
Add-WebConfigurationProperty -Filter "/system.webServer/security/authentication/forms" -Name "cookieless" -Value "UseCookies"

# Ensure cookie protection mode is configured for forms authentication
Add-WebConfigurationProperty -Filter "/system.webServer/security/authentication/forms" -Name "protection" -Value "All"

# Ensure passwordFormat is not set to clear
Add-WebConfigurationProperty -Filter "/system.web/membership/providers/add[@name='ProviderName']" -Name "passwordFormat" -Value "Hashed"

# Ensure credentials are not stored in configuration files
$webapps = Get-WebApplication
foreach ($webapp in $webapps) {
    $physicalPath = $webapp.physicalPath
    $webConfigPath = "$physicalPath\web.config"
    if (Test-Path $webConfigPath) {
        $webConfig = [xml](Get-Content $webConfigPath)
        $credentialsElement = $webConfig.SelectSingleNode("/configuration/system.web/httpRuntime/@enablePasswordRetrieval")
        if ($credentialsElement -ne $null) {
            $credentialsElement.ParentNode.RemoveChild($credentialsElement)
            $webConfig.Save($webConfigPath)
            Write-Host "Removed 'credentials' element from $webConfigPath"
        }
    }
}

# Additional security configurations
Add-WebConfigurationProperty -Filter "/system.webServer/deployment" -Name "Retail" -Value "True"
Set-WebConfigurationProperty -Filter "/system.web/compilation" -Name "debug" -Value "False"
Set-WebConfigurationProperty -Filter "/system.webServer/httpErrors" -Name "errorMode" -Value "DetailedLocalOnly"
Set-WebConfigurationProperty -Filter "/system.web/trace" -Name "enabled" -Value "false"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "mode" -Value "InProc"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "cookieName" -Value "MyAppSession"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "cookieless" -Value "UseCookies"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "timeout" -Value "20"
Add-WebConfigurationProperty -Filter "/configuration/system.web/machineKey" -Name "validation" -Value "3DES"
Add-WebConfigurationProperty -Filter "/configuration/system.web/machineKey" -Name "validation" -Value "SHA1"
Add-WebConfigurationProperty -Filter "/configuration/system.web/trust" -Name "level" -Value "Full"
Set-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']" -PSPath "IIS:\Sites\Default Web Site" -Name "." -Value $null
Add-WebConfigurationProperty -Filter "/system.webServer/httpProtocol/customHeaders" -Name "remove" -Value @{name="X-Powered-By";}
Add-WebConfigurationProperty -Filter "/system.webServer/httpProtocol/customHeaders" -Name "add" -Value @{name="Server";value="";}
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/requestLimits" -Name "maxAllowedContentLength" -Value 104857600
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/requestLimits" -Name "maxUrl" -Value 8192
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/requestLimits" -Name "maxQueryString" -Value 2048
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/allowDoubleEscaping" -Name "enabled" -Value "False"
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/denyUrlSequences" -Name "add" -Value @{sequence="%2525"}
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering" -Name "allowVerb" -Value @{verb="TRACE"; allowed="False"}
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/fileExtensions" -Name "allowUnlisted" -Value "False"
Set-WebConfigurationProperty -Filter "/system.webServer/handlers/*" -Name "permissions" -Value "Read,Script"
Add-WebConfigurationProperty -Filter "/system.webServer/isapiCgiRestriction" -Name "notListedIsapisAllowed" -Value "False"
Add-WebConfigurationProperty -Filter "/system.webServer/isapiCgiRestriction" -Name "notListedCgisAllowed" -Value "False"
Set-WebConfigurationProperty -Filter "/system.webServer/security/dynamicIpSecurity" -Name "enabled" -Value "True"
Add-Item -ItemType Directory -Path "C:\NewLogLocation"
Add-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/logFile" -Name "directory" -Value "C:\NewLogLocation"
Restart-Service W3SVC
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -Filter "system.applicationHost/sites/siteDefaults/Logfile" -Name "logExtFileFlags" -Value "Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus"
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -Filter "system.applicationHost/sites/siteDefaults/tracing/traceFailedRequestsLogging" -Name "enabled" -Value "True"

# FTP Hardening
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FTP\Server' /v "AllowAnonymousTLS" /t REG_DWORD /d 0 /f 
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FTP\Server' /v "MaxFailedAttempts" /t REG_DWORD /d 3 /f 

Write-Host "Script execution complete."


Read-Host "Ensure SSLv2 is Disabled 7.3.    Ensure SSLv3 is Disabled7.4.    Ensure TLS 1.0 is Disabled7.5.    Ensure TLS 1.1 is Disabled" 
reg add  'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v "Enabled" /t REG_DWORD /d 0 /f
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v "Enabled" /t REG_DWORD /d 0 /f
reg add  'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' /v "Enabled" /t REG_DWORD /d 0 /f
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' /v "Enabled" /t REG_DWORD /d 0 /f
Read-Host "Ensure TLS 1.2 is Enabled"
reg add  'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' /v "Enabled" /t REG_DWORD /d 1 /f
Read-Host "ensure NULL, DES, and RC4 cipher suites are disabled"
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' /v "Enabled" /t REG_DWORD /d 0 /f
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' /v "Enabled" /t REG_DWORD /d 0 /f
reg add  'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' /v "Enabled" /t REG_DWORD /d 0 /f
Read-Host "ensure AES 128/128 cipher suite is disabled and AES 256/256 cipher suite is enabled,"
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' /v "Enabled" /t REG_DWORD /d 0 /f
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' /v "Enabled" /t REG_DWORD /d 1 /f
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v 'EnabledCipherSuites' /t REG_DWORD /d "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256" /f
