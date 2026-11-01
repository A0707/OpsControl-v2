# Compatibility entry point: all sources use the encrypted persistent store.
param([switch]$UpdateCredentials)
& (Join-Path $PSScriptRoot 'LANCER-INFRAOPS.ps1') -UpdateCredentials:$UpdateCredentials
