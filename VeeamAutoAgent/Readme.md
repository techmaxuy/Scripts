# Paso 0 — Verifica/instala el módulo correcto
# Abrí PowerShell como Administrador y corré:

# habilitar TLS 1.2 por si tu 5.1 es viejo
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ¿Existe el cmdlet?
Get-Command Register-PSResourceRepository -ErrorAction SilentlyContinue

# Si no devuelve nada, instalá PSResourceGet:
Install-Module Microsoft.PowerShell.PSResourceGet -Scope CurrentUser -Force
Import-Module Microsoft.PowerShell.PSResourceGet -Force

# Confirmá que ahora existe:
Get-Command Register-PSResourceRepository

# ###################################################################################

# Si seguís usando Register-PSRepository/Install-Module (PowerShellGet v2), no te va a servir con GitHub Packages (usa NuGet v3). Para GitHub Packages necesitás PSResourceGet.

# Paso 1 — Registrar GitHub Packages como repositorio NuGet v3

# Reemplazá techmaxuy por tu usuario/organización si fuera distinto.

$owner = 'techmaxuy'
Register-PSResourceRepository -Name 'GitHubPkgs' -Uri "https://nuget.pkg.github.com/$owner/index.json" -Trusted

# GitHub Packages siempre requiere credenciales. PSResourceGet te permite pasarlas en cada operación (-Credential o -ApiKey).


# Paso 3 — Instalar el módulo en servidores (consumo)

En cada servidor:

# 3.1 Registrar el repo (solo la primera vez en ese server)
$owner = 'techmaxuy'
if (-not (Get-PSResourceRepository -Name 'GitHubPkgs' -ErrorAction SilentlyContinue)) {
  Register-PSResourceRepository -Name 'GitHubPkgs' -Uri "https://nuget.pkg.github.com/$owner/index.json" -Trusted
}

# 3.2 Credenciales de lectura (PAT con read:packages)
$sec  = Read-Host 'GitHub PAT (read:packages)' -AsSecureString
$cred = New-Object System.Management.Automation.PSCredential('techmaxuy', $sec)

# 3.3 Instalar el módulo
Install-PSResource -Name 'VeeamAutoAgent' -Repository 'GitHubPkgs' -Credential $cred -Scope AllUsers

# 3.4 Ejecutar tu bootstrap
Import-Module VeeamAutoAgent -Force
Install-VeeamAutoAgent
Register-VeeamAutoAgentTask -IntervalMinutes 5


En servidores:

Update-PSResource -Name 'VeeamAutoAgent' -Repository 'GitHubPkgs' -Credential $cred
# o versión específica:
# Install-PSResource -Name 'VeeamAutoAgent' -Repository 'GitHubPkgs' -Version '0.1.1

# Instalacion manual del modulo
Método 1 (el más simple): copiar la carpeta del módulo ya expandida

No necesitás ningún “repo” ni NuGet. Solo copiar y listo.

En una PC con internet (o tu laptop)

Dejá el módulo armado con esta estructura:

VeeamAutoAgent\
  VeeamAutoAgent.psd1
  VeeamAutoAgent.psm1


(Opcional) Verificá que importe bien:

Import-Module .\VeeamAutoAgent\VeeamAutoAgent.psd1 -Force


Copiá esa carpeta a un pendrive o share interno.

En el servidor sin internet

Pegá la carpeta en la ruta estándar de módulos:

PowerShell 5.1:

C:\Program Files\WindowsPowerShell\Modules\VeeamAutoAgent\<VERSIÓN>\


PowerShell 7+:

C:\Program Files\PowerShell\Modules\VeeamAutoAgent\<VERSIÓN>\


(Usá el número de versión que pusiste en el .psd1, por ej. 0.1.0.)

Importá y ejecutá tu bootstrap:

Import-Module VeeamAutoAgent -Force
Install-VeeamAutoAgent
Register-VeeamAutoAgentTask -IntervalMinutes 5


Tip: confirmá que PowerShell “ve” el módulo:

Get-Module -ListAvailable VeeamAutoAgent | Select Name,Version,Path