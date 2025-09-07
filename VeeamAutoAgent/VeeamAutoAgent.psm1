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

    # Copiar el módulo completo al destino (sobre-escribe con -Force)
    # Fuente: carpeta del módulo actual ($PSScriptRoot es ...\VeeamAutoAgent)
    $src = $PSScriptRoot
    $dst = $p.InstallDir

    if ($PSCmdlet.ShouldProcess("$src -> $dst","Copy module")) {
        Copy-Item -Path (Join-Path $src '*') -Destination $dst -Recurse -Force
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
    $trigger.RepetitionInterval = (New-TimeSpan -Minutes $IntervalMinutes)
    $trigger.RepetitionDuration = [TimeSpan]::MaxValue

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

function Invoke-VeeamAutoAgent {
    <#
    .SYNOPSIS
        Punto de entrada del agente. (Placeholder)
    .DESCRIPTION
        Acá irá la lógica real: comprobar módulo de Veeam, ejecutar jobs, reportar, etc.
        Por ahora, solo deja una traza con fecha/hora para verificar la ejecución.
    #>
    try {
        $logDir = Join-Path 'C:\scripts' 'VeeamAutoAgent\logs'
        if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        $log = Join-Path $logDir ('run-' + (Get-Date -Format 'yyyyMMdd') + '.log')
        "[$(Get-Date -Format 'u')] VeeamAutoAgent ejecutado (stub)." | Out-File -FilePath $log -Append -Encoding utf8
    } catch {
        Write-Error $_
    }
}
