Connect-AzureRmAccount
Select-AzureRmSubscription -Subscription "Azure bajo licencia Open(Converted to EA)"
Get-AzureRmVM | Select-Object Name, {$_.HardwareProfile.Vmsize}


