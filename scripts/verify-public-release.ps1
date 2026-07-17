#Requires -Version 5.1

[CmdletBinding()]
param(
    [string] $RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$forbiddenPathPatterns = @(
    '(?i)(^|[\\/])(_owner_private|server_rescue|release-stage[^\\/]*|授权数据)([\\/]|$)',
    '(?i)\.(pem|pfx|p12|key|dpapi|sqlite|sqlite3|db|zip|7z|rar|exe|dll|pdb)$',
    '(?i)(^|[\\/])(owner-config\.json|auth_config\.json|auth-config\.json|\.env)$'
)
$knownProductionHashes = @(
    'D8F41AC13F93A4AE760BD19897F1F4281F9F31B2ED3216393372446B734D2680',
    '4B1A6AA3076CD203AE6EE694FB3CF080C68F016A4FCCECF5B195E08D024D2C17',
    '48D40EAD52F72BF2363440B68847CEC251F7BBE3CF108F6A70D2E81EAFAE2077',
    'D2E5604BB22CCA380C1CF28F1B48FD4B7F3DF9DE6B8B2F007A49D12FF35546E2',
    'A3261B6824FA709A7D866E2D6A334E0AC8F3DCDBE3551F3611D3E7E885CA33E7',
    '6119928332F1973D749823F805E183BBFA44A3F26AD43E163DA850C78E42CA64'
)
$privateKeyPattern = '-----BEGIN (RSA |EC |OPENSSH |ED25519 )?PRIVATE KEY-----'
$secretAssignmentPattern = '(?im)["'']?[A-Z0-9_.-]*(PASSWORD|PASSWD|TOKEN|SECRET|API[_-]?KEY|PRIVATE[_-]?KEY)[A-Z0-9_.-]*["'']?\s*(?::=|=|:)\s*["''](?!CHANGE_ME|EXAMPLE|YOUR_|TEST_ONLY|REDACTED|\*+|<)[^"'']{8,}["'']'
$textExtensions = @(
    '.cs', '.csproj', '.go', '.mod', '.sum', '.ps1', '.md', '.txt',
    '.json', '.yaml', '.yml', '.toml', '.xml', '.config', '.example', '.gitignore'
)
$generatedDirectoryPattern = '(?i)(^|[\\/])(bin|obj|TestResults|artifacts|publish|\.vs)([\\/]|$)'

function Get-Sha256Hex([string] $Value) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant())
        return ([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-', '')
    }
    finally {
        $sha256.Dispose()
    }
}

function Test-KnownProductionIdentifier([string] $Text) {
    $candidates = @{}
    foreach ($match in [regex]::Matches(
        $Text,
        '(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])')) {
        $candidates[$match.Value] = $true
    }
    foreach ($match in [regex]::Matches(
        $Text,
        '(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b')) {
        $labels = @($match.Value -split '\.')
        for ($index = 0; $index -lt $labels.Count - 1; $index++) {
            $candidates[($labels[$index..($labels.Count - 1)] -join '.')] = $true
        }
    }
    foreach ($pattern in @(
        '(?i)\b[a-z][a-z0-9_-]{3,}\b',
        '(?i)\b[a-z][a-z0-9]{3,}\b'
    )) {
        foreach ($match in [regex]::Matches($Text, $pattern)) {
            $candidates[$match.Value] = $true
        }
    }
    foreach ($match in [regex]::Matches(
        $Text,
        '[\p{IsCJKUnifiedIdeographs}]+')) {
        for ($index = 0; $index -lt $match.Value.Length - 1; $index++) {
            $candidates[$match.Value.Substring($index, 2)] = $true
        }
    }

    foreach ($candidate in $candidates.Keys) {
        if ($knownProductionHashes -contains (Get-Sha256Hex $candidate)) {
            return $true
        }
    }
    return $false
}

$findings = New-Object System.Collections.Generic.List[object]
$files = @(Get-ChildItem -LiteralPath $root -File -Recurse -Force | Where-Object {
    $candidate = $_.FullName.Substring($root.Length).TrimStart('\', '/')
    $_.FullName -notlike (Join-Path $root '.git\*') -and
        $candidate -notmatch $generatedDirectoryPattern
})

foreach ($file in $files) {
    $relative = $file.FullName.Substring($root.Length).TrimStart('\', '/')
    foreach ($pattern in $forbiddenPathPatterns) {
        if ($relative -match $pattern) {
            $findings.Add([pscustomobject]@{ Path = $relative; Category = 'forbidden-path' })
            break
        }
    }

    if ($relative -eq 'scripts\verify-public-release.ps1' -or
        $relative -match '(?i)(public_contract_test\.go|PublicContractTests?\.cs)$') {
        continue
    }

    $extension = [IO.Path]::GetExtension($file.Name).ToLowerInvariant()
    if ($file.Name -eq '.gitignore') {
        $extension = '.gitignore'
    }
    if ($textExtensions -notcontains $extension -or $file.Length -gt 4MB) {
        continue
    }

    try {
        $text = [IO.File]::ReadAllText($file.FullName, [Text.Encoding]::UTF8)
    }
    catch {
        $findings.Add([pscustomobject]@{ Path = $relative; Category = 'unreadable-text' })
        continue
    }

    if ($text -match $privateKeyPattern) {
        $findings.Add([pscustomobject]@{ Path = $relative; Category = 'private-key-material' })
    }
    $isTestSource = $relative -match '(?i)(_test\.go|Tests?\.cs)$'
    if (-not $isTestSource -and $text -match $secretAssignmentPattern) {
        $findings.Add([pscustomobject]@{ Path = $relative; Category = 'non-placeholder-secret' })
    }
    if (Test-KnownProductionIdentifier $text) {
        $findings.Add([pscustomobject]@{ Path = $relative; Category = 'production-identifier' })
    }
}

$uniqueFindings = @($findings | Sort-Object Path, Category -Unique)
if ($uniqueFindings.Count -ne 0) {
    foreach ($finding in $uniqueFindings) {
        Write-Host ("PUBLIC RELEASE BLOCKED [{0}] {1}" -f $finding.Category, $finding.Path)
    }
    exit 1
}

Write-Host ("PUBLIC RELEASE VERIFY PASS ({0} files scanned)." -f $files.Count)
