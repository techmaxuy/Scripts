function Get-VAAPaths {
    [CmdletBinding()]
    param()

    $installRoot = 'C:\scripts'
    $installDir  = Join-Path $installRoot 'VeeamAutoAgent'
    $runnerPath  = Join-Path $installDir  'Run-VeeamAutoAgent.ps1'
    $moduleName  = 'VeeamAutoAgent'
    $taskName    = 'VeeamAutoAgent'

    # Directorio fuente (donde está el módulo actualmente)
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
        throw "Runner no encontrado en $($p.RunnerPath). Primero ejecutá Install-VeeamAutoAgent."
    }

    # Acción: ejecutar PowerShell con el runner
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $p.RunnerPath)

    # Trigger: una sola vez (ahora) con repetición indefinida cada N minutos
    $start = (Get-Date).AddMinutes(1)  # arranca en 1 minuto
    $trigger = New-ScheduledTaskTrigger -Once -At $start
    #$trigger.RepetitionInterval = (New-TimeSpan -Minutes $IntervalMinutes)
    #$trigger.RepetitionDuration = [TimeSpan]::MaxValue

    # Principal: SYSTEM con privilegios altos
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    # Settings: sin superposición, sin límite de tiempo de ejecución
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

    Write-Host "Tarea programada '$($p.TaskName)' registrada. Ejecutará el agente cada $IntervalMinutes minuto(s) sin superponerse."
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


    # Crear/actualizar el runner que importa el módulo desde C:\scripts y ejecuta la función principal
    $runner = @"
# Auto-generado por Install-VeeamAutoAgent
# Runner del agente: importa el módulo y ejecuta la función principal

# Asegurar política de ejecución amigable con tareas programadas
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force | Out-Null

# Importar el módulo desde la carpeta instalada
\$moduleRoot = '$($p.InstallDir)'
\$psd1 = Join-Path \$moduleRoot 'VeeamAutoAgent.psd1'
Import-Module \$psd1 -Force

# Ejecutar la lógica principal del agente
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
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $enc   = [System.Security.Cryptography.ProtectedData]::Protect(
                $bytes, $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [Convert]::ToBase64String($enc)
}

function ConvertFrom-VAAEncryptedBase64 {
    param([Parameter(Mandatory)][string]$CipherText)
    try {
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

# --- NUEVA función pública ---
function Update-VeeamAutoAgentConfig {
    <#
    .SYNOPSIS
        Crea/actualiza el archivo de configuración JSON del agente con valores encriptados.
    .DESCRIPTION
        Valida que la ruta de trabajo exista y tenga lectura/escritura. Escribe:
          C:\scripts\VeeamAutoAgent\Config\config.json
        Los valores se guardan encriptados con DPAPI en scope LocalMachine,
        para que puedan ser leídos por la tarea programada ejecutándose como SYSTEM.
    .PARAMETER RootWorkFolder
        Ruta de trabajo (local o UNC). Debe existir y permitir lectura/escritura.
    .OUTPUTS
        Devuelve la ruta del archivo de configuración generado.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position=0)]
        [Alias('rootWorkFolder','Path')]
        [ValidateNotNullOrEmpty()]
        [string]$RootWorkFolder
    )

    $p = Get-VAAPaths

    # Directorio de configuración y archivo
    $configDir  = Join-Path $p.InstallDir 'Config'
    $configFile = Join-Path $configDir 'config.json'

    # Validación de la ruta de trabajo
    $rw = Test-VAAPathReadWrite -Path $RootWorkFolder
    if (-not $rw.Exists) { throw "La ruta '$RootWorkFolder' no existe o no es un directorio." }
    if (-not $rw.Read)   { throw "No hay permisos de LECTURA en '$RootWorkFolder'." }
    if (-not $rw.Write)  { throw "No hay permisos de ESCRITURA en '$RootWorkFolder'." }

    # Asegurar carpetas de instalación y de config
    if (-not (Test-Path -LiteralPath $p.InstallDir)) { New-Item -ItemType Directory -Path $p.InstallDir -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $configDir))    { New-Item -ItemType Directory -Path $configDir  -Force | Out-Null }

    # Construir el objeto de configuración con valores encriptados (Base64 DPAPI LocalMachine)
    $payload = [ordered]@{
        SchemaVersion  = 1
        UpdatedUtc     = (Get-Date).ToUniversalTime().ToString('u')
        Encrypted      = $true
        Values         = [ordered]@{
            RootWorkFolder = (ConvertTo-VAAEncryptedBase64 -PlainText $RootWorkFolder)
        }
    }

    $json = $payload | ConvertTo-Json -Depth 6

    if ($PSCmdlet.ShouldProcess($configFile, 'Escribir configuración')) {
        $json | Set-Content -Path $configFile -Encoding UTF8
    }

    Write-Host "Configuración escrita en: $configFile"
    return $configFile
}



function Invoke-VeeamAutoAgent {
    <#
    .SYNOPSIS
        Punto de entrada del agente. (Placeholder)
    .DESCRIPTION
        Acá irá la lógica real: comprobar módulo de Veeam, ejecutar jobs, reportar, etc.
        Por ahora, solo deja una traza con fecha/hora para verificar la ejecución.
    #>
    try {

                # === Cargar configuración (RootWorkFolder) ===
        $p = Get-VAAPaths
        $configFile = Join-Path $p.InstallDir 'Config\config.json'
        $workRoot = $null
        $warn = $null

        if (Test-Path -LiteralPath $configFile) {
            $cfg = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
            if ($cfg -and $cfg.Values -and $cfg.Values.RootWorkFolder) {
                $workRoot = if ($cfg.Encrypted) {
                    ConvertFrom-VAAEncryptedBase64 -CipherText $cfg.Values.RootWorkFolder
                } else {
                    [string]$cfg.Values.RootWorkFolder
                }
            }
        }

        # Fallback si no hay config o es inválida
        if (-not $workRoot) { $workRoot = $p.InstallDir }

        # Validar existencia y permisos R/W
        $rw = Test-VAAPathReadWrite -Path $workRoot
        if (-not ($rw.Exists -and $rw.Read -and $rw.Write)) {
            $old = $workRoot
            $workRoot = $p.InstallDir
            $warn = "RootWorkFolder '$old' no es utilizable (Exists=$($rw.Exists) Read=$($rw.Read) Write=$($rw.Write)). Usando '$workRoot'."
        }


        $logDir = Join-Path 'C:\scripts' 'VeeamAutoAgent\logs'
        if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        $log = Join-Path $logDir ('run-' + (Get-Date -Format 'yyyyMMdd') + '.log')
        "[$(Get-Date -Format 'u')] VeeamAutoAgent ejecutado (stub)." | Out-File -FilePath $log -Append -Encoding utf8
    } catch {
        Write-Error $_
    }
}
