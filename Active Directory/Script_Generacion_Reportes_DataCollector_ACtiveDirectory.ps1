# ==============================================================
# === Initialize and Set variable ==============================
# ==============================================================
$StartTime=(Get-Date -format “dd-MMM-yyyy HH:mm”).ToString()
$EndTime=””

$UniqueIps = New-Object System.Collections.Generic.HashSet[String]
$Kerberos = New-Object System.Collections.Generic.HashSet[String]
$NTLM = New-Object System.Collections.Generic.HashSet[String]

$CounterFileLines=0
$CounterDsDirSearch=0
$CounterUniqueIPs=0
$CounterTGSRequest=0
$CounterNtlmValidateUser=0

$IpsReqsArray = @()
$KerberosReqsArray = @()
$NtlmReqsArray = @()

# — Get File Folder and File Name —————————-
$LogFileName = Read-Host “Enter Path to dumpfile.csv”
If ((Test-Path $LogFileName) -eq $false)
{
    Write-Error “File not found”; break
}

# — Get the IP Address of the Source Domain Controller ——-
$SourceDC = Read-Host “Enter IP of Source Domain Controller”

# — Open the Input File for reading (per line) —————
$LogfileReader = [System.IO.File]::OpenText(“$($LogFileName)”)

# — Main loop for processing each line in the file ———–
While ($null -ne ($LogfileLine = $LogfileReader.ReadLine()))
{
$CounterFileLines++
$Class = $LogfileLine.Split(“,”)

# — Check if the line matches a LDAP request —————–
If (($Class[0].Trim() -eq “DsDirSearch”) -and ($Class[1].Trim() -eq “Start”) -and ($Class[24] -like “*.*”) -and ($Class[24] -notlike “*127.0.0.1*”) -and ($Class[24] -notlike “*$($SourceDC)*”))
{
$IsolatedIpAddress=$Class[24].Split(“:”)[0].Replace(“`””,””).TrimStart()

$UniqueIps.Add($($IsolatedIpAddress)) | Out-Null
$CounterDsDirSearch++
Write-Host “Found LDAP Request number $($CounterDsDirSearch) and adding it to the collection” -ForegroundColor Cyan
}

# — Check if the line matches a Kerberos request ————-
ElseIf ($Class[0].Trim() -eq “TGSRequest”)
{
$Kerberos.Add($Class[20..22]) | Out-Null
$CounterTGSRequest++
Write-Host “Found Kerberos request number $($CounterTGSRequest) and adding it to the collection” -ForegroundColor Green
}

# — Check if the line matches a NTLM request —————–
ElseIf ($Class[0].Trim() -eq “NtlmValidateUser”)
{
$NTLM.Add($Class[22..23]) | Out-Null
$CounterNtlmValidateUser++
Write-Host “Found NTLM request number $($CounterNtlmValidateUser) and adding it to the collection” -ForegroundColor Yellow
}
}

$LogfileReader.Close()

# — Process Unique LDAP Requests and write to file ———–
Write-Host
Write-Host “Start Processing All Unique LDAP connection IP’s” -ForegroundColor White
$IpsEnum = $UniqueIps.GetEnumerator()
#Disable, Not supported by Powershell V2
#$IpsEnum.Reset()

While ($IpsEnum.MoveNext())
{
$CounterUniqueIPs++
$RetrievedIp = $(get-variable -name IpsEnum).Value.Current
$IpReqLine = New-Object -TypeName PsObject
Add-Member -InputObject $IpReqLine -MemberType NoteProperty -Name “IP” -Value $RetrievedIp

$IpsReqsArray += $IpReqLine
}
Write-Host “Writing Unique LDAP connection IP’s to log file: $($LogFileName.Substring(0,$LogFileName.LastIndexOf(“\”)+1))Ips.csv” -ForegroundColor White
Write-Host
$IpsReqsArray | Export-Csv -Path “$($LogFileName.Substring(0,$LogFileName.LastIndexOf(“\”)+1))Ips.csv” -NoTypeInformation -Delimiter “`t”

# — Process Kerberos Requests and write to file ————–
Write-Host “Start Processing All Kerberos Items” -ForegroundColor White
$KerberosEnum = $Kerberos.GetEnumerator()
#Disable, Not supported by Powershell V2
#$KerberosEnum.Reset()

While ($KerberosEnum.MoveNext())
{
$RetrievedKerberos = $(get-variable -name KerberosEnum).Value.Current.Replace(“`””, “”).Trim().Replace(” “, “,”).Split(“,”)

$KerberosReqLine = New-Object -TypeName PsObject
Add-Member -InputObject $KerberosReqLine -MemberType NoteProperty -Name “User” -Value $RetrievedKerberos[0]
Add-Member -InputObject $KerberosReqLine -MemberType NoteProperty -Name “Service” -Value $RetrievedKerberos[1]
Add-Member -InputObject $KerberosReqLine -MemberType NoteProperty -Name “Domain” -Value $RetrievedKerberos[2]

$KerberosReqsArray += $KerberosReqLine
}
Write-Host “Writing Kerberos Entries to log file: $($LogFileName.Substring(0,$LogFileName.LastIndexOf(“\”)+1))Kerberos.csv” -ForegroundColor White
Write-Host
$KerberosReqsArray | Export-Csv -Path “$($LogFileName.Substring(0,$LogFileName.LastIndexOf(“\”)+1))Kerberos.csv” -NoTypeInformation -Delimiter “`t”

# — Process NTLM Requests and write to file —————–
Write-Host “Start Processing All NTLM Items” -ForegroundColor White
$NtlmEnum = $Ntlm.GetEnumerator()
#Disable, Not supported by Powershell V2
#$NtlmEnum.Reset()

While ($NtlmEnum.MoveNext())
{
$RetrievedNtlm = $(get-variable -name NtlmEnum).Value.Current.Replace(“`””, “”).Trim().Replace(” “, “,”).Split(“,”)

$NtlmReqLine = New-Object -TypeName PsObject
Add-Member -InputObject $NtlmReqLine -MemberType NoteProperty -Name “User” -Value $RetrievedNtlm[0]
Add-Member -InputObject $NtlmReqLine -MemberType NoteProperty -Name “Computer” -Value $RetrievedNtlm[1]

$NtlmReqsArray += $NtlmReqLine
}
Write-Host “Writing NTLM Entries to log file: $($LogFileName.Substring(0,$LogFileName.LastIndexOf(“\”)+1))Ntlm.csv” -ForegroundColor White
Write-Host
$NtlmReqsArray | Export-Csv -Path “$($LogFileName.Substring(0,$LogFileName.LastIndexOf(“\”)+1))Ntlm.csv” -NoTypeInformation -Delimiter “`t”

# — Display processing statistics —————————
Write-Host “Processed File Lines: $($CounterFileLines)” -ForegroundColor White
Write-Host “Found LDAP Request(s): $($CounterDsDirSearch)” -ForegroundColor Cyan
Write-Host “Found Kerberos Request(s): $($CounterTGSRequest)” -ForegroundColor Green
Write-Host “Found NTLM Request(s): $($CounterNtlmValidateUser)” -ForegroundColor Yellow
Write-Host
Write-Host “Found Unique LDAP IP(s): $($CounterUniqueIPs)” -ForegroundColor Cyan
Write-Host

$EndTime=(Get-Date -format “dd-MMM-yyyy HH:mm”).ToString()

Write-Host “Start Time: $($StartTime)” -ForegroundColor Magenta
Write-Host “End Time: $($EndTime)” -ForegroundColor Magenta
Write-Host

Write-Host “Done !!!” -ForegroundColor White