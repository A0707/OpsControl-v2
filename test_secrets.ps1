$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'InfraOps-Secrets.ps1')
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('infraops-secrets-test-' + [Guid]::NewGuid().ToString('N'))
$testSecret = ConvertTo-SecureString 'fixture-secret-never-use-in-production' -AsPlainText -Force
try {
    Initialize-InfraOpsSecretStore $testRoot
    Initialize-InfraOpsSecretStore $testRoot
    Save-InfraOpsSecret $testRoot 'INFRAOPS_TEST_AUTH' $testSecret
    $testFile = Get-InfraOpsSecretPath $testRoot 'INFRAOPS_TEST_AUTH'
    $testCipher = [IO.File]::ReadAllText($testFile)
    if ($testCipher.Contains('fixture-secret')) { throw 'Plaintext on disk' }
    $loaded = Read-InfraOpsSecret $testRoot 'INFRAOPS_TEST_AUTH'
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($loaded)
    try {
        if ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) -ne 'fixture-secret-never-use-in-production') { throw 'Round trip failed' }
    } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer); $loaded.Dispose() }
    Save-InfraOpsSecret $testRoot 'INFRAOPS_TEST_AUTH' $testSecret
    if ($null -ne (Read-InfraOpsSecret $testRoot 'INFRAOPS_ABSENT_AUTH')) { throw 'Missing should return null' }
    $rejected = $false
    try { Get-InfraOpsSecretPath $testRoot '../bad' | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Path validation failed' }
    $acl = Get-Acl -LiteralPath $testRoot
    if (-not $acl.AreAccessRulesProtected) { throw 'ACL inheritance should be disabled' }
    $expectedSids = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18')
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw 'Expected exactly user and SYSTEM access rules' }
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -notin $expectedSids -or
            $rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or
            $rule.FileSystemRights -ne 'FullControl') { throw 'Unexpected store permission' }
    }
    foreach ($file in @('LANCER-INFRAOPS.ps1','InfraOps-Secrets.ps1')) {
        $tokens = $null; $errors = $null
        $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file), [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw ('Parser: ' + $file) }
    }
    Write-Output 'PASS: DPAPI round trip, ciphertext, overwrite, missing, path validation, ACL and launcher syntax'
} finally {
    $testSecret.Dispose()
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf).StartsWith('infraops-secrets-test-')) {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    }
}
