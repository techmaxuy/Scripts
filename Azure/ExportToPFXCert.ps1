$appServiceCertificateName = "Netorder"
$resourceGroupName = "Res_GRP_Cert"
$azureLoginEmailId = "srodales@megapharma.com"
$subscriptionId = "e3a89e14-6d79-4b70-b5b0-ca87849db5f5"

Login-AzureRmAccount
Set-AzureRmContext -SubscriptionId $subscriptionId

$ascResource = Get-AzureRmResource -ResourceName $appServiceCertificateName -ResourceGroupName $resourceGroupName -ResourceType "Microsoft.CertificateRegistration/certificateOrders" -ApiVersion "2015-08-01"
$keyVaultId = ""
$keyVaultSecretName = ""

$ascResource
Write-Host "-----------"

$certificateProperties=Get-Member -InputObject $ascResource.Properties.certificates[0] -MemberType NoteProperty
$certificateName = $certificateProperties[0].Name
$keyVaultId = $ascResource.Properties.certificates[0].$certificateName.KeyVaultId
$keyVaultSecretName = $ascResource.Properties.certificates[0].$certificateName.KeyVaultSecretName

$keyVaultIdParts = $keyVaultId.Split("/")
$keyVaultName = $keyVaultIdParts[$keyVaultIdParts.Length - 1]
$keyVaultResourceGroupName = $keyVaultIdParts[$keyVaultIdParts.Length - 5]

$keyVaultId
Write-Host "-----------"
$keyVaultName
Write-Host "-----------"

Set-AzureRmKeyVaultAccessPolicy -ResourceGroupName $keyVaultResourceGroupName -VaultName $keyVaultName -UserPrincipalName $azureLoginEmailId -PermissionsToSecrets get
$secret = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $keyVaultSecretName
$pfxCertObject=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @([Convert]::FromBase64String($secret.SecretValueText),"", [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
$pfxPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 50 | % {[char]$_})
$currentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath
[Environment]::CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath
[io.file]::WriteAllBytes(".\appservicecertificate.pfx", $pfxCertObject.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $pfxPassword))
Write-Host "Created an App Service Certificate copy at: $currentDirectory\appservicecertificate.pfx"
Write-Warning "For security reasons, do not store the PFX password. Use it directly from the console as required."
Write-Host "PFX password: $pfxPassword"