# Secrets encrypted with Windows DPAPI; loaded automatically on subsequent starts.
param([switch]$UpdateCredentials, [switch]$Force,
    [ValidateSet('Proxmox','Wazuh','Zabbix','Elastic','Bacula','GLPI')]
    [string[]]$UpdateSources = @())
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$taskPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) { throw 'Environnement .venv introuvable.' }

if (-not $env:INFRAOPS_PORT) { $env:INFRAOPS_PORT = '8001' }
$taskPort = [int]$env:INFRAOPS_PORT
$taskListener = Get-NetTCPConnection -LocalPort $taskPort -State Listen -ErrorAction SilentlyContinue
if ($taskListener) {
    # Message actionnable plutot qu'une impasse : sans le PID ni la commande,
    # on repart lancer « uvicorn app:app » a la main, donc sans les secrets,
    # et toutes les collectes API echouent.
    $taskPid = $taskListener.OwningProcess | Select-Object -First 1
    $taskOwner = Get-CimInstance Win32_Process -Filter "ProcessId=$taskPid" -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Warning ('Le port ' + $taskPort + ' est deja occupe par le PID ' + $taskPid + '.')
    if ($taskOwner) { Write-Host ('  Commande : ' + $taskOwner.CommandLine) }
    Write-Host '  Une instance lancee sans ce script n a AUCUN secret : ses collectes API echouent toutes.'
    Write-Host ''
    Write-Host '  Pour la remplacer, au choix :'
    Write-Host '    - Ctrl+C dans son terminal, puis relancer ce script'
    Write-Host ('    - Stop-Process -Id ' + $taskPid + ' -Force   puis relancer ce script')
    Write-Host '    - .\LANCER-INFRAOPS.ps1 -Force                (arrete l instance et demarre)'
    Write-Host ''
    if (-not $Force) { return }
    Write-Host ('Arret de l instance en cours (PID ' + $taskPid + ')...')
    Stop-Process -Id $taskPid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Nom de la variable -> invite affichee. Laisser vide pour ignorer une source.
$taskSources = [ordered]@{
    'INFRAOPS_PROXMOX_AUTH' = 'Proxmox  - cle API complete (PVEAPIToken=USER@REALM!ID=SECRET)'
    'INFRAOPS_WAZUH_AUTH'   = 'Wazuh    - utilisateur:mot_de_passe'
    'INFRAOPS_ZABBIX_AUTH'  = 'Zabbix   - jeton API seul, sans prefixe'
    'INFRAOPS_ELASTIC_AUTH' = 'Elastic  - ApiKey CLE_ENCODEE'
    'INFRAOPS_BACULA_AUTH'  = 'Bacula   - Basic BASE64(utilisateur:mot_de_passe)'
    'GLPI_APP_TOKEN'        = 'GLPI     - App-Token du client API (Configuration > Generale > API)'
    'GLPI_USER_TOKEN'       = 'GLPI     - jeton API personnel du compte de service'
}

. (Join-Path $PSScriptRoot 'InfraOps-Secrets.ps1')
$taskStore = Join-Path $env:LOCALAPPDATA 'InfraOps\credentials'
Initialize-InfraOpsSecretStore $taskStore
# Use only the variable names declared by configured API connections.
$taskConfig = Join-Path $PSScriptRoot 'data\api-connections.json'
if (Test-Path -LiteralPath $taskConfig) {
    $taskConnections = @(Get-Content -LiteralPath $taskConfig -Raw | ConvertFrom-Json)
    $taskNames = @($taskConnections | ForEach-Object { $_.token_env } | Where-Object { $_ } | Sort-Object -Unique)
} else { $taskNames = @($taskSources.Keys | Where-Object { $_ -notlike 'GLPI_*' }) }

# Reglages NON secrets du poste (hors Git, liste fermee de cles) :
#   data\poste.env : INFRAOPS_LOCAL_OPERATOR (nom declaratif par defaut des actions locales) ;
#   data\glpi.env  : GLPI (tickets ITSM). Les jetons GLPI restent dans le coffre chiffre.
# Sans glpi.env, GLPI reste desactive.
$taskGlpiKeys = @('GLPI_ENABLED','GLPI_BASE_URL','GLPI_ENTITY_ID','GLPI_REQUESTER_ID','GLPI_OBSERVER_GROUP_ID',
    'GLPI_TIMEOUT_SECONDS','GLPI_ALLOW_HTTP','GLPI_HTTP_HOSTS','OPSCONTROL_PUBLIC_URL','INFRAOPS_LOCAL_OPERATOR')
$taskGlpiPrevious = @{}
foreach ($taskSettings in @('data\poste.env', 'data\glpi.env')) {
    $taskGlpiFile = Join-Path $PSScriptRoot $taskSettings
    if (-not (Test-Path -LiteralPath $taskGlpiFile)) { continue }
    foreach ($taskLine in Get-Content -LiteralPath $taskGlpiFile) {
        if ($taskLine -match '^\s*([A-Z_]+)\s*=\s*(.*?)\s*$' -and $Matches[1] -in $taskGlpiKeys) {
            $taskGlpiPrevious[$Matches[1]] = [Environment]::GetEnvironmentVariable($Matches[1], 'Process')
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2].Trim('"'), 'Process')
        }
    }
}
if ($env:GLPI_ENABLED -eq 'true') { $taskNames += @('GLPI_APP_TOKEN', 'GLPI_USER_TOKEN') }
$taskDefined = @()
$taskPrevious = @{}
$taskPriorInterval = $env:INFRAOPS_AUTO_INTERVAL
try {

foreach ($taskName in $taskNames) {
    $null = Get-InfraOpsSecretPath $taskStore $taskName
    $taskExisting = [Environment]::GetEnvironmentVariable($taskName, 'Process')
    $taskPrevious[$taskName] = $taskExisting
    # Invalid inherited values must not reach the child server either.
    [Environment]::SetEnvironmentVariable($taskName, $null, 'Process')
    $taskSecure = $null
    $taskSourceName = @{INFRAOPS_PROXMOX_AUTH='Proxmox';INFRAOPS_WAZUH_AUTH='Wazuh';INFRAOPS_ZABBIX_AUTH='Zabbix';INFRAOPS_ELASTIC_AUTH='Elastic';INFRAOPS_BACULA_AUTH='Bacula';GLPI_APP_TOKEN='GLPI';GLPI_USER_TOKEN='GLPI'}[$taskName]
    if (-not $UpdateCredentials -and $taskSourceName -notin $UpdateSources) {
        if (-not [string]::IsNullOrWhiteSpace($taskExisting)) {
            $taskSecure = ConvertTo-SecureString -String $taskExisting -AsPlainText -Force
        } else { $taskSecure = Read-InfraOpsSecret $taskStore $taskName }
    }
    if ($null -eq $taskSecure) {
        Write-Host ('Configuration : ' + $taskName)
        $taskSecure = Read-InfraOpsCredential $taskName
        if ($null -eq $taskSecure) { continue }
    }
    $taskPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($taskSecure)
    try {
        $taskPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($taskPointer)
        if ([string]::IsNullOrWhiteSpace($taskPlain)) { continue }
        # Controles de forme : une valeur tronquee a la copie produit une erreur
        # d'authentification trompeuse cote produit, pas un message clair.
        # Zabbix : jeton d'API = exactement 64 caracteres hexadecimaux.
        if ($taskName -eq 'INFRAOPS_ZABBIX_AUTH' -and $taskPlain -notmatch '^[0-9a-fA-F]{64}$') {
            Write-Warning ('Zabbix : attendu 64 caracteres hexadecimaux, recu ' + $taskPlain.Length +
                           '. Une valeur tronquee fait repondre « Session terminated, re-login, please ». Recopier avec le bouton Copy to clipboard.')
        }
        # Bacula : Baculum authentifie en Basic, base64 de utilisateur:mot_de_passe.
        if ($taskName -eq 'INFRAOPS_BACULA_AUTH' -and $taskPlain -notmatch '^Basic [A-Za-z0-9+/=]+$') {
            Write-Warning 'Bacula : format attendu « Basic » suivi d''un espace et de base64(utilisateur:mot_de_passe).'
        }
        # Elastic : la cle encodee doit etre precedee de ApiKey.
        if ($taskName -eq 'INFRAOPS_ELASTIC_AUTH' -and $taskPlain -notmatch '^(ApiKey|Basic) ') {
            Write-Warning 'Elastic : la valeur doit commencer par « ApiKey » suivi d''un espace et de la cle encodee.'
        }
        # Wazuh : identifiants, pas un jeton.
        if ($taskName -eq 'INFRAOPS_WAZUH_AUTH' -and $taskPlain -notmatch ':') {
            Write-Warning 'Wazuh : format attendu utilisateur:mot_de_passe, pas un jeton JWT.'
        }
        # Proxmox : en-tete complet, cle seule frequemment collee par erreur.
        if ($taskName -eq 'INFRAOPS_PROXMOX_AUTH' -and $taskPlain -notmatch '^PVEAPIToken=') {
            Write-Warning 'Proxmox : la valeur doit commencer par PVEAPIToken=USER@REALM!ID=SECRET.'
        }
        if (-not (Test-InfraOpsCredentialFormat $taskName $taskPlain)) {
            Write-Warning ($taskName + ' : source ignoree pour ce lancement (format invalide). Valeur non sauvegardee. Attendu : ' + $taskSources[$taskName])
            continue
        }
        Save-InfraOpsSecret $taskStore $taskName $taskSecure
        [Environment]::SetEnvironmentVariable($taskName, $taskPlain, 'Process')
        $taskDefined += $taskName
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($taskPointer)
        $taskPlain = $null
        $taskSecure.Dispose()
    }
}

if ($taskDefined.Count -eq 0) {
    Write-Host 'Aucun secret fourni : les collectes API echoueront avec « Variable du jeton absente ».'
} else {
    Write-Host ('Sources chargees : ' + ($taskDefined -join ', '))
}
Write-Host 'Identifiants memorises avec le chiffrement Windows. Pour les remplacer : .\LANCER-INFRAOPS.ps1 -UpdateCredentials'
$env:INFRAOPS_AUTO_INTERVAL = '300'
# Tunnel Bacula : le code n'a plus de compte par defaut ; ce poste garde son acces actuel
# tant que le compte de service infraops n'est pas autorise sur le serveur Bacula.
# Tunnel facultatif : définir INFRAOPS_BACULA_TUNNEL_TARGET explicitement si nécessaire.
Write-Host 'Collecte automatique au demarrage puis toutes les 5 minutes.'
Write-Host ('Gardez ce terminal ouvert. Interface OpsControl V2 : http://127.0.0.1:' + $taskPort)

& $taskPython (Join-Path $PSScriptRoot 'run_infraops.py')
}
finally {
    foreach ($taskName in $taskPrevious.Keys) { [Environment]::SetEnvironmentVariable($taskName, $taskPrevious[$taskName], 'Process') }
    foreach ($taskName in $taskGlpiPrevious.Keys) { [Environment]::SetEnvironmentVariable($taskName, $taskGlpiPrevious[$taskName], 'Process') }
    [Environment]::SetEnvironmentVariable('INFRAOPS_AUTO_INTERVAL', $taskPriorInterval, 'Process')
    Write-Host 'Environnement restaure. Les identifiants chiffres restent disponibles pour le prochain lancement.'
}
