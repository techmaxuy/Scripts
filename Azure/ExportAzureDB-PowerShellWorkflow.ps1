#
.SYNOPSIS 
    Export Azure SQL DB to blob storage in .bacpac format
.DESCRIPTION 
    This PowerShell workflow runbook script copy Azure SQL DB and Export copied database to blob storage container use below parameters.
 
.PARAMETER ServerName
    Name of the SqlServer
 
.PARAMETER DatabaseName
    Name of the database
 
.PARAMETER CopyDatabaseName
    Name of the Copydatabase
 
.PARAMETER ResourceGroupName
    Name of resource group contains the SqlServer and DatabaseName
 
.PARAMETER $ServerAdmin
    Name of the Server admin Login
 
.PARAMETER $serverPassword
    Input Server admin password
 
.PARAMETER $BaseStorageUri
    Full uri for storage account name include container name https://STORAGE-NAME.blob.core.windows.net/BLOB-CONTAINER-NAME/
 
.PARAMETER $StorageKey
    Storage account access key "YOUR STORAGE KEY" go to storage account --> settings --> select Access Keys --> Copy/Paste key1
 
.NOTES
    This script provided AS IS, Please review the code before executing this on production environment
    For any issue or suggestion please email to: mobaioum@microsoft.com
#>
# ---- Login to Azure ----
workflow ExportAzureDB-PowerShellWorkflowv2 {
     
 
 
            param
                (
                # Name of the Azure SQL Database server
                [parameter(Mandatory=$true)] 
                [string] $ServerName,
         
                # Source Azure SQL Database name 
                [parameter(Mandatory=$true)] 
                [string] $DatabaseName,
         
                # Target Azure SQL Database name 
                [parameter(Mandatory=$true)] 
                [string] $CopyDatabaseName,
         
                # Resource Group Name
                [parameter(Mandatory=$true)] 
                [string] $ResourceGroupName
                 
            )
         
        inlineScript 
        {
        $connectionName = "AzureRunAsConnection"
        try
        {
         
        # Get the connection "AzureRunAsConnection "
        $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName
        "Login to Azure"
        Add-AzureRmAccount `
-ServicePrincipal `
-TenantId $servicePrincipalConnection.TenantId `
-ApplicationId $servicePrincipalConnection.ApplicationId `
-CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint
        }
        catch {
        if (!$servicePrincipalConnection)
        {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
        } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
        }
        }
         
# convert server admin password to secure string
$serverAdmin = "hidden"
$serverPassword = "hidden"
$securePassword = ConvertTo-SecureString -String $serverPassword -AsPlainText -Force
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $serverAdmin, $securePassword
                 
# Generate a unique filename for the BACPAC
$bacpacFilename = "$Using:CopyDatabaseName" + (Get-Date).ToString("yyyy-MM-dd-HH-mm") + ".bacpac"
         
# Storage account info for the BACPAC
$BaseStorageUri = "https://STORAGE-NAME.blob.core.windows.net/BLOB-CONTAINER-NAME"
$BacpacUri = $BaseStorageUri + "/Daily/" + $bacpacFilename
$StorageKeytype = "StorageAccessKey"
$StorageKey = "YOUR STORAGE KEY"
New-AzureRmSqlDatabaseCopy -ResourceGroupName "$Using:ResourceGroupName" -ServerName "$Using:ServerName" -DatabaseName "$Using:DatabaseName" `
    -CopyResourceGroupName "$Using:ResourceGroupName" -CopyServerName "$Using:ServerName" -CopyDatabaseName "$Using:CopyDatabaseName"
         
Write-Output "Azure SQL DB "$Using:CopyDatabaseName" Copy completed"
         
Write-Output "Azure SQL DB "$Using:CopyDatabaseName" Export Started"
         
$exportRequest = New-AzureRmSqlDatabaseExport -ResourceGroupName "$Using:ResourceGroupName" -ServerName "$Using:ServerName" `
-DatabaseName "$Using:CopyDatabaseName" -StorageKeytype $StorageKeytype -StorageKey $StorageKey -StorageUri $BacpacUri `
-AdministratorLogin $creds.UserName -AdministratorLoginPassword $creds.Password
         
        # Check status of the export
        $exportStatus = Get-AzureRmSqlDatabaseImportExportStatus -OperationStatusLink $exportRequest.OperationStatusLink
        [Console]::Write("Exporting")
        while ($exportStatus.Status -eq "InProgress")
        {
        $exportStatus = Get-AzureRmSqlDatabaseImportExportStatus -OperationStatusLink $exportRequest.OperationStatusLink
        Start-Sleep -s 10
        }
        $exportStatus
        $Status= $exportStatus.Status
        if($Status -eq "Succeeded")
        {
        Write-Output "Azure SQL DB Export $Status for "$Using:CopyDatabaseName""
        }
        else
        {
        Write-Output "Azure SQL DB Export Failed for "$Using:CopyDatabaseName""
        }
 
         
# Drop Copy Database after successful export
Remove-AzureRmSqlDatabase -ResourceGroupName "$Using:ResourceGroupName" `
    -ServerName "$Using:ServerName" `
    -DatabaseName "$Using:CopyDatabaseName" `
    -Force
         
        Write-Output "Azure SQL DB "$Using:CopyDatabaseName" Deleted"
        }
        }