Move-Item -Path ".\powershell.exe.config" -Destination "C:\Windows\System32\WindowsPowerShell\v1.0" -f
Set-ExecutionPolicy AllSigned
Write-Host "Set ExecutionPolicy to AllSigned"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "__PSLockdownPolicy" -Value 4
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v "EnableTranscripting" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v "OutputDirectory" /t SZ /d "C:\Windows\System32" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v "EnableInvocationHeader " /t REG_DWORD /d 1 /f
Move-Item -Path ".\powershell_ise.exe.config" -Destination "C:\Windows\System32\WindowsPowerShell\v1.0" -f
