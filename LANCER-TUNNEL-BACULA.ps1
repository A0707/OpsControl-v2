# Foreground tunnel: closing this terminal stops forwarding. No remote command.
param([switch]$RegisterHostKey)
$ErrorActionPreference = 'Stop'
if (-not $env:INFRAOPS_BACULA_TUNNEL_TARGET) { throw 'Définir INFRAOPS_BACULA_TUNNEL_TARGET (utilisateur@hôte autorisé).' }
$taskSsh = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
if (-not (Test-Path -LiteralPath $taskSsh)) { throw 'Client Windows OpenSSH introuvable.' }
$taskData = Join-Path $PSScriptRoot 'data'
[IO.Directory]::CreateDirectory($taskData) | Out-Null
$taskKnownHosts = (Join-Path $taskData 'bacula-known_hosts').Replace('\', '/')
$taskHostCheck = 'yes'
if ($RegisterHostKey) {
    $taskHostCheck = 'ask'
    Write-Host 'Comparer l empreinte SSH affichee avec celle obtenue sur la console Bacula avant de repondre yes.'
}
Write-Host 'Tunnel Bacula : garder ce terminal ouvert. Ctrl+C pour fermer.'
& $taskSsh -N -T -o "StrictHostKeyChecking=$taskHostCheck" -o "UserKnownHostsFile=$taskKnownHosts" -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -L 127.0.0.1:19096:127.0.0.1:9096 $env:INFRAOPS_BACULA_TUNNEL_TARGET
if ($LASTEXITCODE -ne 0) { throw 'Tunnel SSH non etabli. Verifier le message SSH, la cle hote connue et les identifiants SSH.' }
