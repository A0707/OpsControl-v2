$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'InfraOps-Secrets.ps1')
function Read-Host {
    param([string]$Prompt, [switch]$AsSecureString)
    if ($script:answers.Count -eq 0) { throw 'Unexpected prompt' }
    $answer = $script:answers.Dequeue()
    if ($AsSecureString) {
        if ($answer.Length -eq 0) { return New-Object Security.SecureString }
        return ConvertTo-SecureString $answer -AsPlainText -Force
    }
    return $answer
}
function Assert-Credential {
    param($Name, $Inputs, $Expected)
    $script:answers = New-Object 'Collections.Generic.Queue[string]'
    foreach ($entry in $Inputs) { $script:answers.Enqueue($entry) }
    $secret = Read-InfraOpsCredential $Name
    if ($null -eq $Expected) {
        if ($null -ne $secret) { throw 'Skip failed' }
        return
    }
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    try {
        if ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) -cne $Expected) { throw 'Assembly failed' }
        if ($script:answers.Count) { throw 'Retry not consumed' }
    } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer); $secret.Dispose() }
}
Assert-Credential 'INFRAOPS_WAZUH_AUTH' @('', 'fixture-password') 'wazuh-wui:fixture-password'
Assert-Credential 'INFRAOPS_PROXMOX_AUTH' @('audit@pve!read', 'fixture') 'PVEAPIToken=audit@pve!read=fixture'
Assert-Credential 'INFRAOPS_ELASTIC_AUTH' @('dTpw') 'ApiKey dTpw'
Assert-Credential 'INFRAOPS_BACULA_AUTH' @('u', 'p') 'Basic dTpw'
Assert-Credential 'INFRAOPS_ZABBIX_AUTH' @(('a' * 63), ('b' * 64)) ('b' * 64)
Assert-Credential 'INFRAOPS_BACULA_AUTH' @('', '') $null
foreach ($file in @('LANCER-INFRAOPS.ps1','InfraOps-Secrets.ps1')) {
    $tokens=$null; $errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw ('Syntax error: ' + $file) }
}
Write-Output 'PASS: guided credentials for five providers, invalid-token retry, skip and syntax'
