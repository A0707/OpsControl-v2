# OpsControl keeps the existing credential store and launcher options.
param([switch]$UpdateCredentials, [switch]$Force,
    [ValidateSet('Proxmox','Wazuh','Zabbix','Elastic','Bacula')]
    [string[]]$UpdateSources = @())
& (Join-Path $PSScriptRoot 'LANCER-INFRAOPS.ps1') @PSBoundParameters
