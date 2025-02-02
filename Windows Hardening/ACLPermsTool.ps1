# Define the path
$folderPath = Read-Host "please enter a location for this command, all objects in said folder will only give acess to system and admin, while denying everyone, make sure to do this for all major folders"
    
# Get the current ACL of the folder
$acl = Get-Acl $folderPath

# Clear any existing access rules (optional, use with caution)
#$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

# Define access rule for System
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("System", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")

# Define access rule for Administrators
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")

# Define access rule for System
$Everyonerule= New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Modify", "ContainerInherit,ObjectInherit", "None", "Deny")


# Add the access rules to the ACL
$acl.SetAccessRule($systemRule)
$acl.SetAccessRule($adminRule)
$acl.SetAccessRule($Everyonerule)
# Set the modified ACL back to the folder
Set-Acl -Path $folderPath -AclObject $acl

# Propagate the ACL to all child items
Get-ChildItem -Path $folderPath -Recurse | Set-Acl -AclObject $acl
