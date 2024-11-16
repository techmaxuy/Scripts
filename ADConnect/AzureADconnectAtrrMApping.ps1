Import-Module ADSync
$In = @{ }
$Out = @{ }
# Get all Metaverse rules for inbound replication from on-premises AD
$InboundRules = Get-ADSyncRule | ? { $_.Name -like '*In from AD - User*' } | % { $_.AttributeFlowMappings | Select-Object -Property Source, Destination }
($InboundRules | Sort-Object -Property Source | Get-Unique -AsString) | % {
  If ([string]$_.Source -ne '' -and ([string]$_.Source).IndexOf(" ") -le 0 -and -Not $In.Contains([string]$_.Source)) {
    $In.Add([string]$_.Source, [string]$_.Destination)
  }
}
# Get all Metaverse rules for outbound replication to Azure AD
$OutboundRules = Get-ADSyncRule | ? { $_.Name -like '*Out to AAD - User*' } | % { $_.AttributeFlowMappings | Select-Object -Property Source, Destination }
($OutboundRules | Sort-Object -Property Source | Get-Unique -AsString) | % {
  If (-Not $Out.Contains([string]$_.Source)) {
    $Out.Add([string]$_.Source, [string]$_.Destination)
  }
}
# Pair the inbound and outbound rule attributes
$InOut = [System.Collections.ArrayList]@()
$In.Keys | % {
  $InOutObject = [PSCustomObject]@{
    AD        = $_
    Metaverse = $In[$_]
    AAD       = $Out[$In[$_]]
  }
  $InOut += $InOutObject
}
$InOut | Sort-Object -Property AD