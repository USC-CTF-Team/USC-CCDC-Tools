Import-Module .\HardeningKittyGit\HardeningKitty.psm1
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\HardeningKittyGit\lists\finding_list_0x6d69636b_machine.csv -SkipMachineInformation -SkipRestorePoint
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\HardeningKittyGit\lists\finding_list_0x6d69636b_user.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\HardeningKittyGit\lists\finding_list_cis_microsoft_windows_server_2019_1809_1.2.1_user.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\HardeningKittyGit\lists\finding_list_cis_microsoft_windows_server_2019_1809_1.2.1_machine.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\HardeningKittyGit\lists\finding_list_dod_microsoft_windows_server_2019_member_stig_v2r1_user.csv -SkipMachineInformation -SkipRestorePoint
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\HardeningKittyGit\lists\finding_list_dod_microsoft_windows_server_2019_member_stig_v2r1_machine.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\HardeningKittyGit\lists\finding_list_dod_microsoft_windows_server_2019_dc_stig_v2r1_machine.csv -SkipMachineInformation -SkipRestorePoint
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\HardeningKittyGit\lists\finding_list_dod_microsoft_windows_server_2019_dc_stig_v2r1_user.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\HardeningKittyGit\lists\finding_list_dod_windows_defender_antivirus_stig_v2r1.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\HardeningKittyGit\lists\finding_list_dod_windows_firewall_stig_v1r7.csv -SkipMachineInformation -SkipRestorePoint 
