@echo off
rem Double-clic : demarre OpsControl si besoin et ouvre l interface (voir DEMARRER-OPSCONTROL.ps1).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0DEMARRER-OPSCONTROL.ps1" %*
if errorlevel 1 pause
