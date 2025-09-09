@{
    RootModule        = 'VeeamAutoAgent.psm1'
    ModuleVersion     = '0.1.18'
    GUID              = 'b9f0f8a1-8d8f-4a0f-bc5c-5a9a6d3f4a10'
    Author            = 'Maximiliano'
    CompanyName       = 'OpenSource'
    Description       = 'Agente de respaldo Veeam - bootstrap de instalación y tarea programada.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-VAAPaths',
        'Install-VeeamAutoAgent',
        'Register-VeeamAutoAgentTask',
        'Unregister-VeeamAutoAgentTask',
        'Update-VeeamAutoAgentConfig',
        'Invoke-VeeamAutoAgent'
    )
    CmdletsToExport   = @()
    AliasesToExport   = @()
    VariablesToExport = '*'
}

