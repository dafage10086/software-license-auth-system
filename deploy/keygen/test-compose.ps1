#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$composePath = Join-Path $PSScriptRoot 'compose.yaml'
$envPath = Join-Path $PSScriptRoot '.env.example'
$licensePath = Join-Path $PSScriptRoot 'LICENSE_KEYGEN_FCL.md'
$readmePath = Join-Path $PSScriptRoot 'README.md'

foreach ($path in @($composePath, $envPath, $licensePath, $readmePath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing public deployment file: $([IO.Path]::GetFileName($path))"
    }
}

$compose = Get-Content -LiteralPath $composePath -Raw -Encoding UTF8
$envTemplate = Get-Content -LiteralPath $envPath -Raw -Encoding UTF8
$licenseText = Get-Content -LiteralPath $licensePath -Raw -Encoding UTF8

$requiredComposeValues = @(
    'keygen/api:v1.7.0',
    'postgres:17.5-alpine',
    'redis:7.4-alpine',
    'clickhouse/clickhouse-server:25.12-alpine',
    '127.0.0.1:18788:3000',
    'http://127.0.0.1:3000/v1/health',
    'internal: true',
    'no-new-privileges:true'
)
foreach ($value in $requiredComposeValues) {
    if (-not $compose.Contains($value)) {
        throw "compose.yaml is missing required deployment contract: $value"
    }
}

if ([regex]::Matches($compose, '(?m)^\s+ports:\s*$').Count -ne 1) {
    throw 'Only the Keygen web service may publish a port.'
}

$forbiddenComposePatterns = @(
    '(?im)^\s*image:\s*[^#\r\n]*:latest\s*$',
    '0\.0\.0\.0:',
    '\[::\]:',
    '["'']?5432:5432["'']?',
    '["'']?6379:6379["'']?',
    '["'']?8123:8123["'']?'
)
foreach ($pattern in $forbiddenComposePatterns) {
    if ($compose -match $pattern) {
        throw 'compose.yaml exposes an unapproved image or network binding.'
    }
}

$assignments = $envTemplate -split "`r?`n" |
    Where-Object { $_ -match '^[A-Z][A-Z0-9_]*=' }
$safeExactValues = @(
    'redis://redis:6379',
    'CE',
    'singleplayer',
    '1',
    '5'
)
foreach ($assignment in $assignments) {
    $name, $value = $assignment -split '=', 2
    $value = $value.Trim()
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw ".env.example contains an empty value for $name."
    }
    if ($safeExactValues -notcontains $value -and
        $value -notmatch '^(CHANGE_ME|EXAMPLE_|license_auth_example|license_analytics_example)') {
        throw ".env.example contains a non-placeholder value for $name."
    }
}

if ($envTemplate -match '(?i)-----BEGIN .*PRIVATE KEY-----') {
    throw '.env.example contains private key material.'
}
if ($licenseText.Length -lt 4000 -or
    $licenseText -notmatch 'Fair Core License' -or
    $licenseText -notmatch 'FCL-1\.0-ALv2' -or
    $licenseText -notmatch 'Grant of Future License') {
    throw 'Keygen FCL text is incomplete.'
}

Write-Host 'KEYGEN DEPLOY VERIFY PASS'
