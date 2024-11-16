$VMs=Get-AzureRmVM -Status
foreach ($vm in $VMs) {
    $RGName=$vm.ResourceGroupName
    $VMName=$vm.Name 
    $ubicacion=(Get-AzurermResourceGroup -Name $RGName).Location
    $storage=$vm.storageProfile.OsDisk

    
    if ($storage.Vhd.Uri -ne $Null) {
        if ($storage.vhd.Uri -like "*sharep*") {
            Write-Output "Nombre VM: $VMname"
            Write-Output "Resource Group: $RGName"
            Write-Output "Ubicacion: $Ubicacion"

            Write-Output ""
            $storageName=$storage.Name
            $storageUri=$storage.vhd.uri
            $storageAccName=($storage.vhd.uri.split("/")[2]).split(".")[0]
            $storageFileName=$storage.vhd.uri.split("/")[4]

            Write-Output "Disco OS: $storageName"
            Write-Output "Ubicacion: $storageuri"
            Write-Output "Storage Account: $storageAccName"
            Write-Output "Nombre del Archivo: $storageFileName"
            Write-Output ""

            #$ss=$storage.split("/")[2]
            #$ss
            #$OSstorageAccountName=$ss.split(".")[0]
    
            $ddisk=$vm.storageProfile.DataDisks
            foreach ($ddis in $ddisk) {
                $ddis.Vhd.Uri
            }
            Write-Output "................................................................................................."
         }
    }
}

