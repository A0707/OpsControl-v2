param([string]$Model = 'opscontrol-local', [int]$Port = 8001, [string]$LlmUrl = 'http://127.0.0.1:1234/v1')
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$pythonPath = Join-Path $projectRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'Environnement .venv absent : consulter docs/ASSISTANT-IA.md.' }
$env:OPSCONTROL_AI_ENABLED = '1'
$env:OPSCONTROL_AI_MODEL = $Model
$env:OPSCONTROL_AI_URL = $LlmUrl
$env:OPSCONTROL_AI_CODE_READ = '1'
$env:OPSCONTROL_AI_DEV_ENABLED = '0'
if ([string]::IsNullOrEmpty($env:OPSCONTROL_AI_LOCAL_TOKEN)) {
    $env:OPSCONTROL_AI_LOCAL_TOKEN = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
}
Write-Host 'Le serveur et le modèle LM Studio doivent être prêts. Aucun téléchargement automatique.'
Write-Host 'Jeton à saisir dans Assistant IA (conservez cette console privée) :'
Write-Host $env:OPSCONTROL_AI_LOCAL_TOKEN
Write-Host "OpsControl : http://127.0.0.1:$Port/#/Assistant%20IA"
Push-Location -LiteralPath $projectRoot
try { & $pythonPath -m uvicorn app:app --host 127.0.0.1 --port $Port }
finally { Pop-Location }
