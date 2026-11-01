@echo off
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
 echo Python est introuvable. Installer Python 3.11 ou plus recent avec ajout au PATH.
 pause
 exit /b 1
)
if not exist ".venv\Scripts\python.exe" python -m venv .venv
if not exist ".venv\Scripts\python.exe" (
 echo Impossible de creer l'environnement Python.
 pause
 exit /b 1
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
 echo Installation interrompue. Consulter le message ci-dessus.
 pause
 exit /b 1
)
echo Ouvrir http://127.0.0.1:8001 dans le navigateur.
echo Garder ce terminal ouvert. Ctrl+C pour arreter.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0LANCER-INFRAOPS.ps1"
pause
