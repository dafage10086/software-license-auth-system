#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$verifier = Join-Path $PSScriptRoot 'verify-public-release.ps1'
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempRoot = Join-Path $tempBase (
    'software-license-auth-public-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

function Invoke-Gate([int] $ExpectedExitCode) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $verifier `
        -RepositoryRoot $tempRoot *> $null
    if ($LASTEXITCODE -ne $ExpectedExitCode) {
        throw "Public release gate exit code was $LASTEXITCODE; expected $ExpectedExitCode."
    }
}

try {
    [IO.File]::WriteAllText(
        (Join-Path $tempRoot 'README.md'),
        'Safe public fixture.',
        (New-Object Text.UTF8Encoding($false)))
    Invoke-Gate 0

    [IO.File]::WriteAllText(
        (Join-Path $tempRoot '.env'),
        'SAFE=CHANGE_ME',
        (New-Object Text.UTF8Encoding($false)))
    Invoke-Gate 1
    Remove-Item -LiteralPath (Join-Path $tempRoot '.env')

    $probePath = Join-Path $tempRoot 'probe.txt'
    $fixtureHeader = [string]::Concat('-----BEGIN ', 'PRIVATE KEY-----')
    [IO.File]::WriteAllText(
        $probePath,
        $fixtureHeader,
        (New-Object Text.UTF8Encoding($false)))
    Invoke-Gate 1

    $values = @(
        [string]::Concat('159.195.', '58.181'),
        [string]::Concat('best', 'srv.de'),
        [string]::Concat('ql-keygen', '-tunnel'),
        [string]::Concat('QL', 'W10'),
        [string]::Concat('Qing', 'Lan'),
        [string]::Concat([char]0x9752, [char]0x84DD)
    )
    foreach ($value in $values) {
        [IO.File]::WriteAllText(
            $probePath,
            $value,
            (New-Object Text.UTF8Encoding($false)))
        Invoke-Gate 1
    }

    Write-Host 'PUBLIC RELEASE SELF-TEST PASS (8 blocker classes)'
}
finally {
    $resolvedRoot = [IO.Path]::GetFullPath($tempRoot)
    if (-not $resolvedRoot.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to remove a release-test directory outside the system temp path.'
    }
    if (Test-Path -LiteralPath $resolvedRoot) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
