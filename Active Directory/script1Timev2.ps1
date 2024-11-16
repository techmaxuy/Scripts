("{0},{1}" -f "Servidor","Peer") | out-file -FilePath .\salida.txt
Get-Content .\listaServidores.txt | foreach-Object {
$timedata=icm $_ {w32tm /query /peers}
$peer=$timedata | Select-String -Pattern "Peer:"
("{0},{1}" -f $_,$peer) | Out-File -FilePath .\salida.txt -Append
}
