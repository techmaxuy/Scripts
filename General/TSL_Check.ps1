
#Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"


#HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\DisabledByDefault

#Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Recurse | Select PSPath, PSChildName


#CD HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols
 
#Get-ChildItem -Recurse -Path . | Where-Object -Property Name -Like '*Browser*' | Select-Object -Property PSPath


$key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$subkeys = Get-ChildItem -Path $key
foreach ($subkey in $subkeys) {
    Write-Output "Subkey: $($subkey.Name)"
}
break

Get-ItemPropertyValue -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\MyApplication" -Name "Version"


# Get registry value powershell
$key = "HKCU:\Software\MyNewKey"
$value = "MyValueName"
$data = Get-ItemProperty -Path $key -Name $value
Write-Output "The value of $value is: $($data.$value)"


CD HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion
 
Get-ItemProperty 