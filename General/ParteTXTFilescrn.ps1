Param([Parameter(Mandatory=$true)][string]$path,[string]$targetFile)
Import-Module PersonalTools

$Servidor=""

Write-Host Chequeando existencia del archivo destino...... $targetFile -ForegroundColor Yellow
if (Test-Path -Path $targetFile) {
    Write-Host El archivo ya existe...... $targetFile -ForegroundColor Yellow
} else {
    Write-Host Creando archivo destino...... $targetFile -ForegroundColor Yellow
    Set-Content -Path $targetFile -Value "Servidor,FolderPath,SharePath,FileGroups"
}

if (Test-Path -Path $path) {
    Write-Host Analizando archivo origen...... $path -ForegroundColor Yellow
    Get-Content -Path $path | ForEach-Object {
        $i=$i+1
        Write-Host "Leyendo linea:" $i -ForegroundColor Yellow

        if ($_ -match "File screens on machine") {
            $Servidor=Get-Palabra -frase $_.ToString() -ubicacion 5  
        }

        if ($_ -match "File Screen Path:") {
            $folderPath=Get-FileScreenPath -frase $_.ToString()  
        }

        if ($_ -match "Share Path:") {
            $sharePath=Get-SharePath -frase $_.ToString()  
        }

         if ($_ -match "File Groups:") {
            $fileGroups=Get-FileGroups -frase $_.ToString()  

            $auxString=$Servidor+","+$folderPath+","+$sharePath+","+$fileGroups
            Add-Content -path $targetFile -Value $auxString
        }

    }
    

} else {
        Write-Host "No se encuentra el archivo"
}
