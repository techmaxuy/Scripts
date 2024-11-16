
#0 – Install necessary PowerShell Modules, if needed.
Install-Module MSOnline
Import-Module MSOnline

#1 – Get User Immutable ID from Azure.
Connect-MSOLService
Get-MsolUser -UserPrincipalName user@domain.tld | select ImmutableID


#2 – Convert to GUID Format
[GUID][system.convert]::FromBase64String("User ImmutableID")


#3 – Check against AD and check which one is corresponding
$User = Get-ADUser -Identity username -Properties mS-DS-ConsistencyGUID
[GUID]$User.'mS-DS-ConsistencyGUID'
$User.ObjectGUID