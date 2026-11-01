# Démarrage en un double-clic (DEMARRER-OPSCONTROL.cmd ou raccourci du Bureau).
#
# Pourquoi ce script en plus de LANCER-INFRAOPS.ps1 : il fallait ouvrir un terminal,
# lancer le script, attendre, puis taper l'adresse. Ici :
#   - OpsControl répond déjà : le navigateur s'ouvre, rien n'est relancé ;
#   - sinon : LANCER-INFRAOPS.ps1 démarre dans sa propre fenêtre réduite (secrets du
#     coffre Windows, comme d'habitude), puis le navigateur s'ouvre dès que /health/live répond.
# -CreerRaccourci pose un raccourci « OpsControl » sur le Bureau.
# Aucun serveur supervisé n'est modifié : seul le lanceur habituel est appelé.
param([switch]$CreerRaccourci)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

if ($CreerRaccourci) {
    # Icône : le PNG de l'application, enveloppé dans un .ico (format accepté depuis Windows Vista).
    $png = Join-Path $PSScriptRoot 'web\assets\opscontrol-icon-64.png'
    $ico = Join-Path $PSScriptRoot 'data\opscontrol.ico'
    if ((Test-Path -LiteralPath $png) -and -not (Test-Path -LiteralPath $ico)) {
        $image = [IO.File]::ReadAllBytes($png)
        $flux = New-Object IO.MemoryStream
        $ecrit = New-Object IO.BinaryWriter($flux)
        $ecrit.Write([UInt16]0); $ecrit.Write([UInt16]1); $ecrit.Write([UInt16]1)
        $ecrit.Write([Byte]64); $ecrit.Write([Byte]64); $ecrit.Write([Byte]0); $ecrit.Write([Byte]0)
        $ecrit.Write([UInt16]1); $ecrit.Write([UInt16]32); $ecrit.Write([UInt32]$image.Length); $ecrit.Write([UInt32]22)
        $ecrit.Write($image)
        New-Item -ItemType Directory -Force (Split-Path $ico) | Out-Null
        [IO.File]::WriteAllBytes($ico, $flux.ToArray())
    }
    $lien = Join-Path ([Environment]::GetFolderPath('Desktop')) 'OpsControl.lnk'
    $raccourci = (New-Object -ComObject WScript.Shell).CreateShortcut($lien)
    $raccourci.TargetPath = Join-Path $PSScriptRoot 'DEMARRER-OPSCONTROL.cmd'
    $raccourci.WorkingDirectory = $PSScriptRoot
    $raccourci.WindowStyle = 7   # réduit : la fenêtre d'attente ne masque rien
    $raccourci.Description = 'Démarrer OpsControl et ouvrir l''interface'
    if (Test-Path -LiteralPath $ico) { $raccourci.IconLocation = $ico }
    $raccourci.Save()
    Write-Host ('Raccourci créé : ' + $lien)
    return
}

$port = if ($env:INFRAOPS_PORT) { [int]$env:INFRAOPS_PORT } else { 8001 }
$url = 'http://127.0.0.1:' + $port

function Test-OpsControl {
    try { return (Invoke-WebRequest ($url + '/health/live') -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
    catch { return $false }
}

if (Test-OpsControl) {
    Write-Host ('OpsControl est déjà démarré : ouverture de ' + $url)
    Start-Process $url
    return
}

# Port pris par autre chose qu'OpsControl : le lanceur affiche le PID et la marche à suivre.
$lanceur = Join-Path $PSScriptRoot 'LANCER-INFRAOPS.ps1'
Write-Host 'Démarrage d''OpsControl dans la fenêtre « OpsControl » (réduite dans la barre des tâches)...'
Start-Process powershell.exe -WindowStyle Minimized -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit',
    '-Command', ('$Host.UI.RawUI.WindowTitle = ''OpsControl - ne pas fermer''; & ''' + $lanceur.Replace("'", "''") + ''''))

# Démarrage typique : 5 à 20 s (tunnel Bacula, migrations, première sonde).
$limite = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $limite) {
    Start-Sleep -Seconds 2
    if (Test-OpsControl) {
        Write-Host ('OpsControl est prêt : ouverture de ' + $url)
        Start-Process $url
        return
    }
    Write-Host -NoNewline '.'
}
Write-Host ''
Write-Warning ('OpsControl ne répond pas après 90 s. Ouvrir la fenêtre « OpsControl - ne pas fermer » ' +
               'dans la barre des tâches pour lire le message.')
Read-Host 'Entrée pour fermer'
