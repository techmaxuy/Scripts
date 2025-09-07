Paso 0 — Verifica/instala el módulo correcto

Abrí PowerShell como Administrador y corré:

# habilitar TLS 1.2 por si tu 5.1 es viejo
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ¿Existe el cmdlet?
Get-Command Register-PSResourceRepository -ErrorAction SilentlyContinue

# Si no devuelve nada, instalá PSResourceGet:
Install-Module Microsoft.PowerShell.PSResourceGet -Scope CurrentUser -Force
Import-Module Microsoft.PowerShell.PSResourceGet -Force

# Confirmá que ahora existe:
Get-Command Register-PSResourceRepository


Si seguís usando Register-PSRepository/Install-Module (PowerShellGet v2), no te va a servir con GitHub Packages (usa NuGet v3). Para GitHub Packages necesitás PSResourceGet.

Paso 1 — Registrar GitHub Packages como repositorio NuGet v3

Reemplazá techmaxuy por tu usuario/organización si fuera distinto.

$owner = 'techmaxuy'
Register-PSResourceRepository -Name 'GitHubPkgs' -Uri "https://nuget.pkg.github.com/$owner/index.json" -Trusted


GitHub Packages siempre requiere credenciales. PSResourceGet te permite pasarlas en cada operación (-Credential o -ApiKey).

Paso 2 — Publicar tu módulo VeeamAutoAgent en GitHub Packages
$modulePath = 'C:\Portfolio\Scripts\VeeamAutoAgent'

# PAT con scope write:packages (y repo si el paquete está ligado a un repo privado)
$sec  = Read-Host 'Ingresa tu GitHub PAT (write:packages)' -AsSecureString
$cred = New-Object System.Management.Automation.PSCredential('techmaxuy', $sec)

Publish-PSResource -Path $modulePath -Repository 'GitHubPkgs' -Credential $cred


Asegurate de que tu VeeamAutoAgent.psd1 tenga ModuleVersion, RootModule, etc.
Si te da “401/403”, revisá el scope del PAT.

Paso 3 — Instalar el módulo en servidores (consumo)

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

Paso 4 — Actualizar versiones

Sube ModuleVersion en el .psd1.

Volvé a publicar:

Publish-PSResource -Path 'C:\Portfolio\Scripts\VeeamAutoAgent' -Repository 'GitHubPkgs' -Credential $cred


En servidores:

Update-PSResource -Name 'VeeamAutoAgent' -Repository 'GitHubPkgs' -Credential $cred
# o versión específica:
# Install-PSResource -Name 'VeeamAutoAgent' -Repository 'GitHubPkgs' -Version '0.1.1