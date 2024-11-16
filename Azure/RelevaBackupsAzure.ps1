#Connect-AzureRmAccount
#Select-AzureRmSubscription -Subscription "Azure bajo licencia Open(Converted to EA)"
$vaults=Get-AzureRmRecoveryServicesVault
ForEach ($baul in $vaults) {
    #$path = Get-AzureRmRecoveryServicesVaultSettingsFile -Vault $baul     #(No siempre Necesario)
    #Import-AzureRmRecoveryServicesAsrVaultSettingsFile -Path $path.filepath #(No siempre Necesario)
    Set-AzureRmRecoveryServicesVaultContext -Vault $baul
    Get-AzureRmRecoveryServicesBackupContainer -ContainerType AzureVM
}

