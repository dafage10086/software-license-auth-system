#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$readmePaths = @(
    (Join-Path $repositoryRoot 'README.md'),
    (Join-Path $repositoryRoot 'README_EN.md')
)
$requiredValues = @(
    '924211252',
    'keygen/api:v1.7.0',
    '/api/v2/login',
    '/api/v2/activate',
    '/api/v2/lease',
    '/api/v2/logout',
    'AGPL-3.0-only',
    'FCL-1.0-ALv2'
)
$chineseContact = 'QQ' + [char]0x7FA4 + [char]0xFF1A + '924211252'
$expectedContacts = @{
    'README.md' = $chineseContact
    'README_EN.md' = 'QQ group: 924211252'
}

foreach ($path in $readmePaths) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing synchronized README: $([IO.Path]::GetFileName($path))"
    }

    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    foreach ($value in $requiredValues) {
        if (-not $content.Contains($value)) {
            throw "$([IO.Path]::GetFileName($path)) is missing required value: $value"
        }
    }
    $fileName = [IO.Path]::GetFileName($path)
    if (-not $content.Contains($expectedContacts[$fileName])) {
        throw "$fileName is missing its exact collaboration contact."
    }
}

Write-Host 'DOCUMENTATION SYNC VERIFY PASS'
