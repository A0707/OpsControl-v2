# Windows DPAPI: ciphertext is decryptable only by this Windows account.
function Test-InfraOpsCredentialFormat {
    param([string]$Name, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '[\r\n]') { return $false }
    switch ($Name) {
        'INFRAOPS_PROXMOX_AUTH' { return $Value -cmatch '^PVEAPIToken=[^\s=!]+![^\s=]+=\S+$' }
        'INFRAOPS_WAZUH_AUTH' { return $Value -match '^[^:]+:.+$' }
        'INFRAOPS_ZABBIX_AUTH' { return $Value -match '^[0-9a-fA-F]{64}$' }
        'INFRAOPS_ELASTIC_AUTH' {
            if ($Value -cnotmatch '^(ApiKey|Basic) (\S+)$') { return $false }
            try { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[2])).Contains(':') }
            catch { return $false }
        }
        'INFRAOPS_BACULA_AUTH' {
            if ($Value -cnotmatch '^Basic (\S+)$') { return $false }
            try { return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1])).Contains(':') }
            catch { return $false }
        }
        default { return $true }
    }
}

function Read-InfraOpsCredential {
    param([string]$Name)
    # Secret values are read masked and assembled only in process memory.
    while ($true) {
        $prefix = ''
        $basic = $false
        switch ($Name) {
            'INFRAOPS_WAZUH_AUTH' {
                $user = Read-Host 'Utilisateur API Wazuh [Entree = wazuh-wui]'
                if (-not $user) { $user = 'wazuh-wui' }
                $prefix = $user + ':'
                $label = 'Mot de passe API Wazuh (pas un JWT)'
            }
            'INFRAOPS_PROXMOX_AUTH' {
                $identity = Read-Host 'Identifiant public du jeton Proxmox : USER@REALM!TOKENID'
                $prefix = 'PVEAPIToken=' + $identity + '='
                $label = 'Secret du jeton Proxmox'
            }
            'INFRAOPS_ELASTIC_AUTH' { $prefix = 'ApiKey '; $label = 'Cle Elastic au format Encoded (sans ApiKey)' }
            'INFRAOPS_ZABBIX_AUTH' { $label = 'Jeton Zabbix complet : 64 caracteres' }
            'INFRAOPS_BACULA_AUTH' {
                $user = Read-Host 'Utilisateur API Baculum'
                $prefix = $user + ':'; $basic = $true
                $label = 'Mot de passe API Baculum'
            }
            default { $label = $Name }
        }
        $secret = Read-Host ($label + ' [Entree = ignorer cette source]') -AsSecureString
        if ($secret.Length -eq 0) { $secret.Dispose(); return $null }
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
        try {
            $value = $prefix + [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
            if ($basic) { $value = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($value)) }
            if (Test-InfraOpsCredentialFormat $Name $value) {
                return ConvertTo-SecureString $value -AsPlainText -Force
            }
            Write-Warning 'Format incomplet ou invalide. Recommencez, ou laissez le secret vide pour ignorer cette source.'
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
            $secret.Dispose(); $value = $null
        }
    }
}

function Initialize-InfraOpsSecretStore {
    param([Parameter(Mandatory)][string]$Directory)
    [IO.Directory]::CreateDirectory($Directory) | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    foreach ($sid in @($owner, $system)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    # Persist only the modified access rules (DACL). Set-Acl can also request
    # audit-policy access (SACL), which requires SeSecurityPrivilege.
    # Keep the existing owner and audit rules; no administrator rights needed
    # for a directory the current user owns and can change permissions on.
    $directoryInfo = New-Object IO.DirectoryInfo($Directory)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [IO.FileSystemAclExtensions]::SetAccessControl($directoryInfo, $acl)
    } else {
        $directoryInfo.SetAccessControl($acl)
    }
}
function Get-InfraOpsSecretPath {
    param([string]$Directory, [string]$Name)
    if ($Name -notmatch '^[A-Z][A-Z0-9_]{0,100}$') { throw 'Nom de variable invalide.' }
    return Join-Path $Directory ($Name + '.dpapi')
}
function Save-InfraOpsSecret {
    param([string]$Directory, [string]$Name, [Security.SecureString]$Secret)
    $file = Get-InfraOpsSecretPath $Directory $Name
    $temporary = $file + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $backup = $temporary + '.backup'
    try {
        # Une fenêtre Windows PowerShell ouverte depuis PowerShell 7 peut hériter
        # de chemins de modules incompatibles : charger celui de son propre moteur.
        Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
        $encrypted = ConvertFrom-SecureString -SecureString $Secret
        [IO.File]::WriteAllText($temporary, $encrypted, [Text.Encoding]::ASCII)
        if ([IO.File]::Exists($file)) { [IO.File]::Replace($temporary, $file, $backup) }
        else { [IO.File]::Move($temporary, $file) }
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
        if ([IO.File]::Exists($backup)) { [IO.File]::Delete($backup) }
    }
}
function Read-InfraOpsSecret {
    param([string]$Directory, [string]$Name)
    $file = Get-InfraOpsSecretPath $Directory $Name
    if (-not [IO.File]::Exists($file)) { return $null }
    try { return ConvertTo-SecureString -String ([IO.File]::ReadAllText($file)) -ErrorAction Stop }
    catch { throw ('Secret illisible pour ' + $Name + '. Relancer avec -UpdateCredentials sous le compte Windows d''origine.') }
}
