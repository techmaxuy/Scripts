function Write-VaaLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$LogDir = (Join-Path 'C:\scripts' 'VeeamAutoAgent\logs')
    )
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $log = Join-Path $LogDir ('run-' + (Get-Date -Format 'yyyyMMdd') + '.log')
    "[{0}] {1}" -f (Get-Date -Format 'u'), $Message | Out-File -FilePath $log -Append -Encoding utf8
}



function Get-VAAPaths {
    [CmdletBinding()]
    param()

    $installRoot = 'C:\scripts'
    $installDir  = Join-Path $installRoot 'VeeamAutoAgent'
    $runnerPath  = Join-Path $installDir  'Run-VeeamAutoAgent.ps1'
    $moduleName  = 'VeeamAutoAgent'
    $taskName    = 'VeeamAutoAgent'

    # Directorio fuente (donde esta el modulo actualmente)
    $sourceDir = Split-Path -Parent $PSScriptRoot

    [pscustomobject]@{
        InstallRoot = $installRoot
        InstallDir  = $installDir
        RunnerPath  = $runnerPath
        SourceDir   = $sourceDir
        ModuleName  = $moduleName
        TaskName    = $taskName
    }
}


function Register-VeeamAutoAgentTask {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$IntervalMinutes = 5,
        [switch]$Force
    )

    if ($IntervalMinutes -lt 1) {
        throw "IntervalMinutes debe ser >= 1."
    }

    $p = Get-VAAPaths

    if (!(Test-Path $p.RunnerPath)) {
        throw "Runner no encontrado en $($p.RunnerPath). Primero ejecuta Install-VeeamAutoAgent."
    }

    # Accion: ejecutar PowerShell con el runner
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $p.RunnerPath)

    # Trigger: una sola vez (ahora) con repeticion indefinida cada N minutos
    $start = (Get-Date).AddMinutes(1)  # arranca en 1 minuto
    $trigger = New-ScheduledTaskTrigger -Once -At $start
    #$trigger.RepetitionInterval = (New-TimeSpan -Minutes $IntervalMinutes)
    #$trigger.RepetitionDuration = [TimeSpan]::MaxValue

    # Principal: SYSTEM con privilegios altos
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    # Settings: sin superposicion, sin limite de tiempo de ejecucion
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew `
        -StartWhenAvailable

    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

    if ($PSCmdlet.ShouldProcess($p.TaskName, "Register-ScheduledTask")) {
        try {
            Register-ScheduledTask -TaskName $p.TaskName -InputObject $task -Force:$Force | Out-Null
        } catch {
            if (-not $Force) {
                throw $_
            } else {
                Unregister-ScheduledTask -TaskName $p.TaskName -Confirm:$false -ErrorAction SilentlyContinue
                Register-ScheduledTask -TaskName $p.TaskName -InputObject $task -Force | Out-Null
            }
        }
    }

    Write-Host "Tarea programada '$($p.TaskName)' registrada. Ejecutara el agente cada $IntervalMinutes minuto(s) sin superponerse."
}


function Install-VeeamAutoAgent {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$Force
    )

    $p = Get-VAAPaths


    if (!(Test-Path $p.InstallRoot)) {
        New-Item -ItemType Directory -Path $p.InstallRoot -Force | Out-Null
    }
    if (!(Test-Path $p.InstallDir)) {
        New-Item -ItemType Directory -Path $p.InstallDir -Force | Out-Null
    }


    # Crear/actualizar el runner que importa el modulo desde C:\scripts y ejecuta la funcion principal
    $runner = @"
# Auto-generado por Install-VeeamAutoAgent
# Runner del agente: importa el modulo y ejecuta la funcion principal

# Asegurar politica de ejecucion amigable con tareas programadas
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force | Out-Null

# Importar el modulo desde la carpeta instalada

Import-Module VeeamAutoAgent -Force

# Ejecutar la logica principal del agente
Invoke-VeeamAutoAgent
"@

    Set-Content -Path $p.RunnerPath -Value $runner -Encoding UTF8

    Write-Host "VeeamAutoAgent instalado en $($p.InstallDir)"
    Write-Host "Runner creado en $($p.RunnerPath)"
    Register-VeeamAutoAgentTask -Force

}


function Unregister-VeeamAutoAgentTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $p = Get-VAAPaths
    if (Get-ScheduledTask -TaskName $p.TaskName -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess($p.TaskName,"Unregister-ScheduledTask")) {
            Unregister-ScheduledTask -TaskName $p.TaskName -Confirm:$false
            Write-Host "Tarea '$($p.TaskName)' eliminada."
        }
    } else {
        Write-Host "La tarea '$($p.TaskName)' no existe."
    }
}

# --- Helpers privados DPAPI (no exportar) ---
function ConvertTo-VAAEncryptedBase64 {
    param([Parameter(Mandatory)][string]$PlainText)

    if (-not ('System.Security.Cryptography.ProtectedData' -as [Type])) {
    Add-Type -AssemblyName 'System.Security'
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $enc   = [System.Security.Cryptography.ProtectedData]::Protect(
                $bytes, $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [Convert]::ToBase64String($enc)
}

function ConvertFrom-VAAEncryptedBase64 {
    param([Parameter(Mandatory)][string]$CipherText)
    try {
        if (-not ('System.Security.Cryptography.ProtectedData' -as [Type])) {
            Add-Type -AssemblyName 'System.Security'
        }
        $bytes = [Convert]::FromBase64String($CipherText)
        $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
                    $bytes, $null,
                    [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        return [System.Text.Encoding]::UTF8.GetString($plain)
    } catch {
        throw "No se pudo desencriptar el valor: $($_.Exception.Message)"
    }
}


function Test-VAAPathReadWrite {
    param([Parameter(Mandatory)][string]$Path)

    $result = [pscustomobject]@{ Exists = $false; Read = $false; Write = $false }

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $result }
    $result.Exists = $true

    try {
        Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop | Out-Null
        $result.Read = $true
    } catch {}

    try {
        $tmpName = [System.IO.Path]::GetRandomFileName()
        $tmpFile = Join-Path -Path $Path -ChildPath $tmpName
        [System.IO.File]::WriteAllText($tmpFile, 'probe')
        Remove-Item -LiteralPath $tmpFile -Force -ErrorAction SilentlyContinue
        $result.Write = $true
    } catch {}

    return $result
}

# --- NUEVA funcion publica ---
function Update-VeeamAutoAgentWorkFolder {
    <#
    .SYNOPSIS
        Crea/actualiza el archivo de configuracion JSON del agente con valores encriptados.
    .DESCRIPTION
        Valida que la ruta de trabajo exista y tenga lectura/escritura. Escribe:
          C:\scripts\VeeamAutoAgent\Config\config.json
        Los valores se guardan encriptados con DPAPI en scope LocalMachine,
        para que puedan ser leidos por la tarea programada ejecutandose como SYSTEM.
    .PARAMETER RootWorkFolder
        Ruta de trabajo (local o UNC). Debe existir y permitir lectura/escritura.
    .OUTPUTS
        Devuelve la ruta del archivo de configuracion generado.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position=0)]
        [Alias('rootWorkFolder','Path')]
        [ValidateNotNullOrEmpty()]
        [string]$WorkFolder
    )

    $p = Get-VAAPaths

    # Directorio de configuracion y archivo
    $configDir  = Join-Path $p.InstallDir 'Config'
    $configFile = Join-Path $configDir 'config.json'

    # Validacion de la ruta de trabajo
    $rw = Test-VAAPathReadWrite -Path $WorkFolder
    if (-not $rw.Exists) { throw "La ruta '$WorkFolder' no existe o no es un directorio." }
    if (-not $rw.Read)   { throw "No hay permisos de LECTURA en '$WorkFolder'." }
    if (-not $rw.Write)  { throw "No hay permisos de ESCRITURA en '$WorkFolder'." }

    # Asegurar carpetas de instalacion y de config
    if (-not (Test-Path -LiteralPath $p.InstallDir)) { New-Item -ItemType Directory -Path $p.InstallDir -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $configDir))    { New-Item -ItemType Directory -Path $configDir  -Force | Out-Null }

    # Construir el objeto de configuracion con valores encriptados (Base64 DPAPI LocalMachine)
    $payload = [ordered]@{
        SchemaVersion  = 1
        UpdatedUtc     = (Get-Date).ToUniversalTime().ToString('u')
        Encrypted      = $true
        Values         = [ordered]@{
            WorkFolder = (ConvertTo-VAAEncryptedBase64 -PlainText $WorkFolder)
        }
    }

    $json = $payload | ConvertTo-Json -Depth 6

    if ($PSCmdlet.ShouldProcess($configFile, 'Escribir configuracion')) {
        $json | Set-Content -Path $configFile -Encoding UTF8
    }

    Write-Host "Configuracion escrita en: $configFile"
    return $configFile
}

function Update-VeeamAutoAgentRoles {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [string[]]$AddRole,
    [string[]]$RemoveRole,
    [switch]$List,
    [switch]$Clear
  )

  $p = Get-VAAPaths
  $configDir  = Join-Path $p.InstallDir 'Config'
  $configFile = Join-Path $configDir 'config.json'
  if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }

  # Cargar o base mínima
  if (Test-Path $configFile) {
    $cfg = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
  } else {
    if (-not ('System.Security.Cryptography.ProtectedData' -as [Type])) { Add-Type -AssemblyName 'System.Security' }
    $encRoot = ConvertTo-VAAEncryptedBase64 -PlainText $p.InstallDir
    $cfg = [pscustomobject]@{
      SchemaVersion = 1
      UpdatedUtc    = (Get-Date).ToUniversalTime().ToString('u')
      Encrypted     = $true
      Values        = [pscustomobject]@{ RootWorkFolder = $encRoot }
      Roles         = @()
    }
  }

  # Leer roles actuales (raíz preferida; compat si quedaron en Values)
  $roles = @()
  if ($cfg.PSObject.Properties.Name -contains 'Roles' -and $cfg.Roles) { $roles = @($cfg.Roles) }
  elseif ($cfg.Values -and $cfg.Values.Roles) { $roles = @($cfg.Values.Roles) }

  if ($List) { ($roles -join ', ') ; return }

  # Crear propiedad Roles en raíz si no existe (PS 5.1 no permite asignar propiedades nuevas directo)
  if (-not ($cfg.PSObject.Properties.Name -contains 'Roles')) {
    $cfg | Add-Member -MemberType NoteProperty -Name 'Roles' -Value @() -Force
  }

  if ($Clear) {
    $cfg.Roles = @()
  } else {
    $set = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $roles) { if ($r) { [void]$set.Add($r) } }

    foreach ($r in ($AddRole | Where-Object { $_ })) {
      switch ($r.ToLowerInvariant()) {
        'backupreport' { [void]$set.Add('BackupReport') }
        default        { Write-Warning "Rol no reconocido: '$r'. Se ignora." }
      }
    }
    foreach ($r in ($RemoveRole | Where-Object { $_ })) { [void]$set.Remove($r) }

    # Asignar ahora que la propiedad existe
    $cfg.Roles = @($set)
  }

  # Limpiar compat en Values (si existiera)
  if ($cfg.Values -and $cfg.Values.PSObject.Properties.Name -contains 'Roles') {
    $cfg.Values.PSObject.Properties.Remove('Roles') | Out-Null
  }

  $cfg.UpdatedUtc = (Get-Date).ToUniversalTime().ToString('u')
  $json = $cfg | ConvertTo-Json -Depth 8
  if ($PSCmdlet.ShouldProcess($configFile, 'Actualizar roles')) {
    $json | Set-Content -Path $configFile -Encoding UTF8
  }
  Write-VaaLog ("Update-VeeamAutoAgentRoles: Roles = {0}" -f (($cfg.Roles) -join ', '))
  ,$cfg.Roles
}







function Invoke-VAA-Task-BackupReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkRoot
    )

    # --- role logger (separate file) ---
    function Write-VaaRoleLog {
        param(
            [Parameter(Mandatory)][string]$Message,
            [Parameter(Mandatory)][string]$RoleName
        )
        $p = Get-VAAPaths
        $baseLogs = Join-Path $p.InstallDir 'logs'
        $roleDir  = Join-Path (Join-Path $baseLogs 'roles') $RoleName
        if (-not (Test-Path $roleDir)) { New-Item -ItemType Directory -Path $roleDir -Force | Out-Null }
        $file = Join-Path $roleDir ("{0}-{1}.log" -f $RoleName, (Get-Date -Format 'yyyyMMdd'))
        "[{0}] {1}" -f (Get-Date -Format 'u'), $Message | Out-File -FilePath $file -Append -Encoding utf8
    }

    # --- HTML helpers ---
    function New-VAAHtmlPage {
        param(
            [Parameter(Mandatory)][string]$Title,
            [Parameter(Mandatory)][string]$BodyHtml
        )
        @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>$Title</title>
<style>
  :root { --bg:#0b1220; --card:#111a2b; --muted:#8aa0c2; --accent:#3ea6ff; --ok:#28c76f; --warn:#ff9f43; --err:#ea5455; --text:#e3ecff; }
  body{margin:0;font-family:Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text)}
  .wrap{max-width:1100px;margin:32px auto;padding:0 16px}
  .title{font-size:28px;font-weight:700;margin:8px 0 16px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin:16px 0}
  .card{background:var(--card);border-radius:14px;padding:18px;box-shadow:0 2px 10px rgba(0,0,0,.25)}
  .metric{font-size:34px;font-weight:800;margin:4px 0 2px}
  .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
  a, a:visited{color:var(--accent);text-decoration:none}
  table{width:100%;border-collapse:collapse;margin-top:12px}
  th,td{padding:10px;border-bottom:1px solid #1e2a44}
  th{text-align:left;color:var(--muted);font-weight:600}
  .ok{color:var(--ok)} .warn{color:var(--warn)} .err{color:var(--err)}
  .breadcrumb{color:var(--muted);font-size:13px;margin-bottom:8px}
  .footer{color:var(--muted);font-size:12px;margin-top:24px}
</style>
</head>
<body>
  <div class="wrap">
    $BodyHtml
    <div class="footer">Generated by VeeamAutoAgent · $(Get-Date -Format 'u')</div>
  </div>
</body>
</html>
"@
    }

    function Save-VAAHtml {
        param(
            [Parameter(Mandatory)][string]$Path,
            [Parameter(Mandatory)][string]$Title,
            [Parameter(Mandatory)][string]$BodyHtml
        )
        (New-VAAHtmlPage -Title $Title -BodyHtml $BodyHtml) | Set-Content -Path $Path -Encoding UTF8
    }

function New-HtmlTable {
        param(
            [Parameter(Mandatory)][Object[]]$Rows,  # array of PSObjects/dicts
            [Parameter(Mandatory)][string[]]$Columns,
            [hashtable]$Headers = $null
        )
        if (-not $Headers) { $Headers = @{} }
        $th = ($Columns | ForEach-Object {
            $hdr = $null
            if ($Headers -and $Headers.ContainsKey($_)) { $hdr = $Headers[$_] } else { $hdr = $_ }
            "<th>{0}</th>" -f $hdr
        }) -join ""
        $trs = foreach ($r in $Rows) {
            $tds = foreach ($c in $Columns) {
                $val = $null
                if ($r.PSObject.Properties.Name -contains $c) { $val = $r.$c }
                elseif ($r.ContainsKey($c)) { $val = $r[$c] }
                "<td>{0}</td>" -f ($val -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;')
            }
            "<tr>$($tds -join '')</tr>"
        }
        "<table><thead><tr>$th</tr></thead><tbody>$($trs -join '')</tbody></table>"
    }

    # --- role starts ---
    $role = 'BackupReport'
    Write-VaaRoleLog -RoleName $role -Message "Role[$role] start. WorkRoot='$WorkRoot'"
    Write-VaaLog ("Role[{0}] started, separate log enabled." -f $role)

    try {
        # Ensure Veeam module
        $veeMod = Get-Module -ListAvailable -Name 'Veeam.Backup.PowerShell' | Select-Object -First 1
        if (-not $veeMod) {
            Write-VaaRoleLog -RoleName $role -Message "Veeam.Backup.PowerShell module not found. Skipping report generation."
            return
        }
        Import-Module 'Veeam.Backup.PowerShell' -ErrorAction Stop

        # Validate WorkRoot
        if (-not (Test-Path -LiteralPath $WorkRoot -PathType Container)) {
            Write-VaaRoleLog -RoleName $role -Message ("WorkRoot does not exist: '{0}'" -f $WorkRoot)
            return
        }

        # Input CSV
        $csvName = 'maquinasvirtuales.csv'
        $csvPath = Join-Path $WorkRoot $csvName
        if (-not (Test-Path -LiteralPath $csvPath -PathType Leaf)) {
            Write-VaaRoleLog -RoleName $role -Message ("Input file '{0}' not found in WorkRoot '{1}'. No report generated." -f $csvName, $WorkRoot)
            return
        }

        $vmsRaw = @()
        try {
            $vmsRaw = Import-Csv -LiteralPath $csvPath -ErrorAction Stop
        } catch {
            Write-VaaRoleLog -RoleName $role -Message ("ERROR reading '{0}': {1}" -f $csvPath, $_.Exception.Message)
            return
        }

        # Resolve VM names from CSV (accept 'VMName','Name','VM'; fallback: first property)
        $vmNames = New-Object System.Collections.Generic.List[string]
        foreach ($row in $vmsRaw) {
            $n = $null
            foreach ($cand in @('VMName','Name','VM')) {
                if ($row.PSObject.Properties.Name -contains $cand -and $row.$cand) { $n = [string]$row.$cand; break }
            }
            if (-not $n) {
                $first = $row.PSObject.Properties.Name | Select-Object -First 1
                if ($first) { $n = [string]$row.$first }
            }
            if ($n) { [void]$vmNames.Add($n.Trim()) }
        }
        $vmNames = $vmNames | Select-Object -Unique
        $totalVMs = $vmNames.Count
        Write-VaaRoleLog -RoleName $role -Message ("Loaded {0} VM(s) from CSV." -f $totalVMs)

        # Time windows
        $nowLocal = Get-Date
        $since24UTC = $nowLocal.AddHours(-24).ToUniversalTime()
        $since7UTC  = $nowLocal.AddDays(-7).ToUniversalTime()
        $since30UTC = $nowLocal.AddDays(-30).ToUniversalTime()

        # Gather sessions in last 30 days (covers 24h & 7d filters too)
        $sessions30 = Get-VBRBackupSession | Where-Object { $_.EndTimeUTC -ge $since30UTC }
        $taskMap = @{}  # Key: VMName(lower), Value: list of task sessions (hashtables with Name, Status, EndTimeUTC, JobName)
        foreach ($sess in $sessions30) {
            $tasks = $null
            try { $tasks = Get-VBRTaskSession -Session $sess } catch { $tasks = $sess.GetTaskSessions() }
            foreach ($t in $tasks) {
                $name = $t.Name
                if ([string]::IsNullOrWhiteSpace($name)) { continue }
                $key = $name.ToLowerInvariant()
                if (-not $taskMap.ContainsKey($key)) { $taskMap[$key] = New-Object System.Collections.Generic.List[object] }
                $obj = [ordered]@{
                    Name        = $name
                    Status      = "$($t.Status)"
                    EndTimeUTC  = $t.EndTimeUTC
                    JobName     = $sess.JobName
                }
                $taskMap[$key].Add([pscustomobject]$obj)
            }
        }

        # Restore points (to detect last backup time / never backed)
        $rpCache = @{}  # key lower -> latest restore point UTC
        foreach ($vm in $vmNames) {
            try {
                $rp = Get-VBRRestorePoint -Name $vm -ErrorAction SilentlyContinue |
                      Sort-Object -Property @{Expression={if($_.PSObject.Properties.Name -contains 'CreationTimeUTC'){ $_.CreationTimeUTC } else { $_.CreationTime }}} -Descending |
                      Select-Object -First 1
                if ($rp) {
                    $rpUtc = if ($rp.PSObject.Properties.Name -contains 'CreationTimeUTC') { $rp.CreationTimeUTC } else { $rp.CreationTime.ToUniversalTime() }
                    $rpCache[$vm.ToLowerInvariant()] = $rpUtc
                }
            } catch {
                Write-VaaRoleLog -RoleName $role -Message ("WARN: failed to query restore point for VM '{0}': {1}" -f $vm, $_.Exception.Message)
            }
        }

        # Classify VMs
        $errors24  = New-Object System.Collections.Generic.List[object]
        $no30d     = New-Object System.Collections.Generic.List[object]
        $never     = New-Object System.Collections.Generic.List[object]
        $succ7d    = New-Object System.Collections.Generic.List[object]

        foreach ($vm in $vmNames) {
            $k = $vm.ToLowerInvariant()
            $tasks = @()
            if ($taskMap.ContainsKey($k)) { $tasks = $taskMap[$k] | Sort-Object EndTimeUTC -Descending }

            # Errors in last 24h
            $err = $tasks | Where-Object { $_.Status -eq 'Failed' -and $_.EndTimeUTC -ge $since24UTC } | Select-Object -First 1
            if ($err) {
                $errors24.Add([pscustomobject]@{
                    VMName = $vm
                    Job    = $err.JobName
                    When   = [DateTime]$err.EndTimeUTC
                    Status = $err.Status
                })
            }

            # Success in last 7 days
            $ok = $tasks | Where-Object { $_.Status -eq 'Success' -and $_.EndTimeUTC -ge $since7UTC } | Select-Object -First 1
            if ($ok) {
                $succ7d.Add([pscustomobject]@{
                    VMName = $vm; Job = $ok.JobName; When = [DateTime]$ok.EndTimeUTC; Status = $ok.Status
                })
            }

            # Last restore point / never backed
            $lastRpUtc = $rpCache[$k]
            if (-not $lastRpUtc) {
                $never.Add([pscustomobject]@{ VMName = $vm })
            } else {
                if ($lastRpUtc -lt $since30UTC) {
                    $no30d.Add([pscustomobject]@{
                        VMName = $vm
                        LastRestorePointUTC = [DateTime]$lastRpUtc
                        DaysSince = [math]::Round( ((Get-Date).ToUniversalTime() - [DateTime]$lastRpUtc).TotalDays, 1 )
                    })
                }
            }
        }

        # Report folder
        $p = Get-VAAPaths
        $repRoot = Join-Path $p.InstallDir 'Reports'
        if (-not (Test-Path $repRoot)) { New-Item -ItemType Directory -Path $repRoot -Force | Out-Null }
        $ts = Get-Date -Format 'yyyyMMdd-HHmmss'

        # Filenames
        $indexHtml   = Join-Path $repRoot "index.html"
        $errHtml     = Join-Path $repRoot "errors-last-24h.html"
        $no30Html    = Join-Path $repRoot "not-backed-last-30d.html"
        $neverHtml   = Join-Path $repRoot "never-backed.html"
        $succ7Html   = Join-Path $repRoot "success-last-7d.html"

        # Save subpages
        Save-VAAHtml -Path $errHtml -Title "VMs with Errors in Last 24h" -BodyHtml (@"
<div class="breadcrumb"><a href="./index.html">&larr; Back to dashboard</a></div>
<div class="title">VMs with Errors in Last 24h</div>
$(Html-Table -Rows ($errors24 | Sort-Object When -Descending) -Columns @('VMName','Job','When','Status') -Headers @{VMName='VM Name'; Job='Job Name'; When='When (UTC)'; Status='Status'})
"@)

        Save-VAAHtml -Path $no30Html -Title "VMs Not Backed Up in Last 30 Days" -BodyHtml (@"
<div class="breadcrumb"><a href="./index.html">&larr; Back to dashboard</a></div>
<div class="title">VMs Not Backed Up in Last 30 Days</div>
$(Html-Table -Rows ($no30d | Sort-Object DaysSince -Descending) -Columns @('VMName','LastRestorePointUTC','DaysSince') -Headers @{VMName='VM Name'; LastRestorePointUTC='Last Restore Point (UTC)'; DaysSince='Days Since'})
"@)

        Save-VAAHtml -Path $neverHtml -Title "VMs Never Backed Up" -BodyHtml (@"
<div class="breadcrumb"><a href="./index.html">&larr; Back to dashboard</a></div>
<div class="title">VMs Never Backed Up</div>
$(Html-Table -Rows $never -Columns @('VMName') -Headers @{VMName='VM Name'})
"@)

        Save-VAAHtml -Path $succ7Html -Title "VMs with Successful Backup in Last 7 Days" -BodyHtml (@"
<div class="breadcrumb"><a href="./index.html">&larr; Back to dashboard</a></div>
<div class="title">VMs with Successful Backup in Last 7 Days</div>
$(Html-Table -Rows ($succ7d | Sort-Object When -Descending) -Columns @('VMName','Job','When','Status') -Headers @{VMName='VM Name'; Job='Job Name'; When='When (UTC)'; Status='Status'})
"@)

        # Dashboard
$body = @"
<div class="title">Veeam Backup Report Dashboard</div>
<div class="grid">
  <div class="card">
    <div class="metric">$totalVMs</div>
    <div class="label">Total VMs</div>
  </div>
  <div class="card">
    <div class="metric err">$($errors24.Count)</div>
    <div class="label"><a href="./errors-last-24h.html">Errors in Last 24h</a></div>
  </div>
  <div class="card">
    <div class="metric warn">$($no30d.Count)</div>
    <div class="label"><a href="./not-backed-last-30d.html">Not Backed in Last 30 Days</a></div>
  </div>
  <div class="card">
    <div class="metric warn">$($never.Count)</div>
    <div class="label"><a href="./never-backed.html">Never Backed Up</a></div>
  </div>
  <div class="card">
    <div class="metric ok">$($succ7d.Count)</div>
    <div class="label"><a href="./success-last-7d.html">Successful in Last 7 Days</a></div>
  </div>
</div>
<p><strong>Generated:</strong> $(Get-Date -Format 'u')</p>
"@
        Save-VAAHtml -Path $indexHtml -Title "Veeam Backup Report Dashboard" -BodyHtml $body

        Write-VaaRoleLog -RoleName $role -Message ("Report generated at '{0}' (index.html) [VMs={1}, Err24h={2}, No30d={3}, Never={4}, OK7d={5}]" -f $repRoot,$totalVMs,$($errors24.Count),$($no30d.Count),$($never.Count),$($succ7d.Count))
        Write-VaaLog ("Role[{0}] report generated in '{1}'." -f $role, $repRoot)

    } catch {
        Write-VaaRoleLog -RoleName $role -Message ("ERROR in role execution: {0}" -f $_.Exception.Message)
    } finally {
        Write-VaaRoleLog -RoleName $role -Message "Role[BackupReport] end."
    }
}




function Invoke-VeeamAutoAgent {
    <#
    .SYNOPSIS
        Punto de entrada del agente (lee config, valida WorkRoot, cuenta "tareas", etc.)
    #>
    try {
       # --- Asegurar ensamblado System.Security disponible ---
        try {
            # Intento “ligero”: si ya esta, no hace nada
            if (-not ('System.Security.Cryptography.ProtectedData' -as [Type])) {
                # Carga explicita del ensamblado
                Add-Type -AssemblyName 'System.Security' -ErrorAction Stop
            }
            Write-VaaLog "System.Security cargado OK."
        } catch {
            Write-VaaLog ("ERROR cargando System.Security: {0}" -f $_.Exception.Message)
        }


        # Arranque
        Write-VaaLog "VeeamAutoAgent iniciado."

        # === Cargar configuracion (RootWorkFolder) ===
        $p = Get-VAAPaths
        $configFile = Join-Path $p.InstallDir 'Config\config.json'
        $workRoot = $null
        $warn = $null

        if (Test-Path -LiteralPath $configFile) {
            try {
                $cfg = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
                Write-VaaLog "Config file leido: $configFile"

                # Acepta RootWorkFolder (correcto) o WorkFolder (compat)
                $cipher = $null
                if ($cfg -and $cfg.Values) {
                    if ($cfg.Values.RootWorkFolder) { $cipher = $cfg.Values.RootWorkFolder }
                    elseif ($cfg.Values.WorkFolder) { $cipher = $cfg.Values.WorkFolder }
                }

                if ($cipher) {
                    if ($cfg.Encrypted) {
                        try {
                            $workRoot = ConvertFrom-VAAEncryptedBase64 -CipherText $cipher
                        } catch {
                            Write-VaaLog ("ERROR desencriptando RootWorkFolder: " + ($_.Exception.Message))
                            $workRoot = $null
                        }
                    } else {
                        $workRoot = [string]$cipher
                    }
                }
            } catch {
                Write-VaaLog ("ERROR leyendo config.json: " + ($_.Exception.Message))
            }
        } else {
            Write-VaaLog "Archivo de configuracion no encontrado en '$configFile'. Usando carpeta de instalacion."
        }

        # Fallback si no hay config o es invalida
        if (-not $workRoot) { $workRoot = $p.InstallDir }

        # Validar existencia y permisos R/W
        $rw = Test-VAAPathReadWrite -Path $workRoot
        if (-not ($rw.Exists -and $rw.Read -and $rw.Write)) {
            $old = $workRoot
            $workRoot = $p.InstallDir
            $warn = "RootWorkFolder '$old' no es utilizable (Exists=$($rw.Exists) Read=$($rw.Read) Write=$($rw.Write)). Usando '$workRoot'."
            Write-VaaLog $warn
        }

        Write-VaaLog ("Usando RootWorkFolder: {0}" -f $workRoot)
        Write-VaaLog "Logica del agente iniciada (stub)."

        # === Leer Roles del config ===
        $roles = @()
        try {
            # $cfg viene del bloque previo donde leíste config.json
            if ($cfg) {
                if ($cfg.PSObject.Properties.Name -contains 'Roles' -and $cfg.Roles) {
                    $roles = @($cfg.Roles)
                } elseif ($cfg.Values -and $cfg.Values.Roles) { # compat si alguna vez guardaste bajo Values
                    $roles = @($cfg.Values.Roles)
                }
            }
        } catch {
            Write-VaaLog ("WARN leyendo roles: {0}" -f $_.Exception.Message)
        }

        if ($roles.Count -gt 0) {
            Write-VaaLog ("Roles activos: {0}" -f ($roles -join ', '))
            # === Tareas por rol (se ejecutan en cada invocación) ===
            foreach ($role in $roles) {
                switch (($role -as [string]).ToLowerInvariant()) {
                    'backupreport' {
                        Invoke-VAA-Task-BackupReport -WorkRoot $workRoot
                    }
                    default {
                        Write-VaaLog ("WARN rol desconocido/ no soportado: {0}" -f $role)
                    }
                }
            }
        } else {
            Write-VaaLog "No hay roles configurados; se omiten tareas por invocación."
        }


        # === Conteo de "tareas" (archivos) en la carpeta de trabajo ===
        try {
            # NO recursivo; solo archivos
            $files = Get-ChildItem -LiteralPath $workRoot -File -Force -ErrorAction Stop
            $taskCount = ($files | Measure-Object).Count

            if ($taskCount -gt 0) {
                Write-VaaLog ("Tareas encontradas: {0}" -f $taskCount)
            } else {
                Write-VaaLog ("No se encontraron tareas en '{0}'." -f $workRoot)
            }
        } catch {
            Write-VaaLog ("ERROR al listar '{0}': {1}" -f $workRoot, ($_.Exception.Message))
        }

        Write-VaaLog "VeeamAutoAgent finalizado."
    } catch {
        # Asegura que los errores queden en el log (tambien si fallo algo antes)
        $msg = "EXCEPTION: " + ($_.Exception | Out-String)
        try { Write-VaaLog $msg } catch { }
        throw
    }
}

function Test-VeeamAutoAgent {
    <#
    .SYNOPSIS
        Diagnostico integral del agente (entorno, config, permisos, tarea programada).
    .OUTPUTS
        PSCustomObject con el detalle del diagnostico y OverallPass.
    #>
    [CmdletBinding()]
    param()

    $result = [ordered]@{
        TimestampUtc      = (Get-Date).ToUniversalTime().ToString('u')
        PSVersion         = $PSVersionTable.PSVersion.ToString()
        Is64BitProcess    = [Environment]::Is64BitProcess
        ModulePath        = $null
        ModuleVersion     = $null
        DPAPIAvailable    = $false
        ConfigPath        = $null
        ConfigEncrypted   = $null
        ConfigReadOk      = $false
        ConfigDecryptOk   = $false
        WorkRoot          = $null
        WorkRootExists    = $false
        WorkRootCanRead   = $false
        WorkRootCanWrite  = $false
        TaskRegistered    = $false
        TaskUser          = $null
        TaskRunLevel      = $null
        TaskAction        = $null
        TaskArguments     = $null
        TaskUsesRunner    = $false
        TaskTriggerOK     = $false
        NextRunTime       = $null
        LastRunTime       = $null
        LastTaskResult    = $null
        State             = $null
        OverallPass       = $false
        Notes             = @()
    }

    try {
        # --- Asegurar ensamblado System.Security disponible ---
        try {
            if (-not ('System.Security.Cryptography.ProtectedData' -as [Type])) {
                Add-Type -AssemblyName 'System.Security' -ErrorAction Stop
            }
            $result.DPAPIAvailable = $true
            Write-VaaLog "System.Security cargado OK."
        } catch {
            Write-VaaLog ("ERROR cargando System.Security: {0}" -f $_.Exception.Message)
            $result.Notes += "System.Security no disponible: $($_.Exception.Message)"
        }

        # --- Modulo actual ---
        $mod = Get-Module VeeamAutoAgent
        if (-not $mod) {
            # Si no esta cargado (raro dentro del propio modulo), intenta resolver el mas nuevo disponible
            $mod = Get-Module VeeamAutoAgent -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
        }
        if ($mod) {
            $result.ModulePath    = $mod.Path
            $result.ModuleVersion = $mod.Version.ToString()
        }
        Write-VaaLog ("PS = {0}; Proc = {1}-bit; Module = {2}; Version = {3}" -f `
            $result.PSVersion, ($(if($result.Is64BitProcess){'64'}else{'32'})), $result.ModulePath, $result.ModuleVersion)

        # --- Paths / Config ---
        $p = Get-VAAPaths
        $configFile = Join-Path $p.InstallDir 'Config\config.json'
        $result.ConfigPath = $configFile

        $workRoot = $null
        if (Test-Path -LiteralPath $configFile) {
            try {
                $cfg = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
                $result.ConfigReadOk    = $true
                $result.ConfigEncrypted = [bool]$cfg.Encrypted
                Write-VaaLog "Config leido: $configFile"

                $cipher = $null
                if ($cfg -and $cfg.Values) {
                    if ($cfg.Values.RootWorkFolder) { $cipher = $cfg.Values.RootWorkFolder }
                    elseif ($cfg.Values.WorkFolder) { $cipher = $cfg.Values.WorkFolder } # compat
                }

                if ($cipher) {
                    if ($cfg.Encrypted) {
                        try {
                            if (-not $result.DPAPIAvailable) { throw "DPAPI no disponible" }
                            $workRoot = ConvertFrom-VAAEncryptedBase64 -CipherText $cipher
                            $result.ConfigDecryptOk = $true
                        } catch {
                            $result.ConfigDecryptOk = $false
                            $result.Notes += "Fallo desencriptando RootWorkFolder: $($_.Exception.Message)"
                            Write-VaaLog ("ERROR desencriptando RootWorkFolder: {0}" -f $_.Exception.Message)
                        }
                    } else {
                        $workRoot = [string]$cipher
                        $result.ConfigDecryptOk = $true
                    }
                } else {
                    $result.Notes += "Config sin RootWorkFolder/WorkFolder."
                    Write-VaaLog "Config sin RootWorkFolder/WorkFolder."
                }
            } catch {
                $result.ConfigReadOk = $false
                $result.Notes += "Fallo leyendo config.json: $($_.Exception.Message)"
                Write-VaaLog ("ERROR leyendo config.json: {0}" -f $_.Exception.Message)
            }
        } else {
            $result.Notes += "Config no encontrado; usando carpeta de instalacion."
            Write-VaaLog "Config no encontrado; usando carpeta de instalacion."
        }

        if (-not $workRoot) { $workRoot = $p.InstallDir }
        $result.WorkRoot = $workRoot

        # --- Validacion R/W de WorkRoot ---
        $rw = Test-VAAPathReadWrite -Path $workRoot
        $result.WorkRootExists = [bool]$rw.Exists
        $result.WorkRootCanRead = [bool]$rw.Read
        $result.WorkRootCanWrite = [bool]$rw.Write

        if ($result.WorkRootExists -and $result.WorkRootCanRead -and $result.WorkRootCanWrite) {
            Write-VaaLog ("WorkRoot OK: {0} (R/W)" -f $workRoot)
        } else {
            Write-VaaLog ("WARN WorkRoot no utilizable: {0} (Exists={1} Read={2} Write={3})" -f `
                $workRoot, $result.WorkRootExists, $result.WorkRootCanRead, $result.WorkRootCanWrite)
            $result.Notes += "WorkRoot no utilizable."
        }

                # --- Tarea programada ---
            $task = Get-ScheduledTask -TaskName $p.TaskName -ErrorAction SilentlyContinue
            if ($task) {
                $result.TaskRegistered = $true

                # Principal (con guardas)
                $result.TaskUser     = ($task.Principal.UserId    | ForEach-Object { $_ }) # null-safe
                $result.TaskRunLevel = if ($task.Principal.RunLevel) { [string]$task.Principal.RunLevel } else { $null }


                # Accion y argumentos (guardado por si no hay acciones)
                $act = $null
                try { $act = $task.Actions | Select-Object -First 1 } catch {}
                if ($act) {
                    $result.TaskAction    = $act.Execute
                    $result.TaskArguments = $act.Arguments
                }

                # ¿Apunta al runner correcto?
                $runnerOk = $false
                if ($result.TaskArguments) {
                    $runnerOk = ($result.TaskArguments -like ("*-File*{0}*" -f $p.RunnerPath)) -or
                                ($result.TaskArguments -like ("*`"{0}`"*" -f $p.RunnerPath))
                }
                $result.TaskUsesRunner = $runnerOk

                # Trigger con repeticion (segun version de Windows puede variar la propiedad)
                $result.TaskTriggerOK = $false
                try {
                    $t = $task.Triggers | Select-Object -First 1
                    if ($t) {
                        $repInt = $null
                        if ($t.PSObject.Properties.Name -contains 'RepetitionInterval') {
                            $repInt = $t.RepetitionInterval
                        } elseif ($t.Repetition -and $t.Repetition.Interval) {
                            $repInt = $t.Repetition.Interval
                        }
                        if ($repInt -and ($repInt -ne [TimeSpan]::Zero)) { $result.TaskTriggerOK = $true }
                    }
                } catch {}

                ## Info dinamica (puede devolver $null: tolerarlo)
                $ti = $null
                try { $ti = Get-ScheduledTaskInfo -TaskName $p.TaskName -ErrorAction Stop } catch {}

                # Inicializar en null-safe
                $result.NextRunTime    = $null
                $result.LastRunTime    = $null
                $result.LastTaskResult = $null
                $result.State          = $null

                if ($ti) {
                    # Algunas propiedades pueden no existir segun version de SO / estado de la tarea
                    if ($ti.PSObject.Properties.Name -contains 'NextRunTime')    { $result.NextRunTime    = $ti.NextRunTime }
                    if ($ti.PSObject.Properties.Name -contains 'LastRunTime')    { $result.LastRunTime    = $ti.LastRunTime }
                    if ($ti.PSObject.Properties.Name -contains 'LastTaskResult') { $result.LastTaskResult = $ti.LastTaskResult }
                    if ($ti.PSObject.Properties.Name -contains 'State' -and $ti.State) {
                        $result.State = [string]$ti.State
                    }
                } else {
                    $result.Notes += "Get-ScheduledTaskInfo devolvio NULL (tarea deshabilitada/permiso/glitch)."
                }


                Write-VaaLog ("Task '{0}': User={1}; RunLevel={2}; Action={3}; RunnerOK={4}; TriggerOK={5}; Next={6}; LastResult={7}; State={8}" -f `
                    $p.TaskName, $result.TaskUser, $result.TaskRunLevel, $result.TaskAction, $result.TaskUsesRunner, $result.TaskTriggerOK, $result.NextRunTime, $result.LastTaskResult, $result.State)
            } else {
                Write-VaaLog ("Task '{0}' NO registrada." -f $p.TaskName)
                $result.Notes += "Tarea no registrada."
            }


        # --- Overall ---
        $result.OverallPass =
            $result.DPAPIAvailable -and
            $result.ConfigReadOk -and
            $result.ConfigDecryptOk -and
            $result.WorkRootExists -and
            $result.WorkRootCanRead -and
            $result.WorkRootCanWrite -and
            $result.TaskRegistered -and
            $result.TaskUsesRunner -and
            $result.TaskTriggerOK


        Write-VaaLog ("TEST RESULT: {0}" -f ($(if ($result.OverallPass) { 'PASS' } else { 'FAIL' })))
        return [pscustomobject]$result
    } catch {
        Write-VaaLog ("EXCEPTION en Test-VeeamAutoAgent: {0}" -f $_.Exception.Message)
        throw
    }
}
