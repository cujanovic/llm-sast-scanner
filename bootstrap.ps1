Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Program = 'llm-sast-scanner-bootstrap'
$Repository = 'https://github.com/cujanovic/llm-sast-scanner'
$Ref = 'main'
$Forward = New-Object Collections.Generic.List[string]
function Fail([string] $Message) { [Console]::Error.WriteLine("$Program`: error: $Message"); exit 1 }

$arguments = @($args)
for ($index = 0; $index -lt $arguments.Count; $index++) {
    if ($arguments[$index] -ceq '--ref') {
        if (++$index -ge $arguments.Count) { Fail '--ref requires a tag or commit' }
        $Ref = [string]$arguments[$index]
    } else { [void]$Forward.Add([string]$arguments[$index]) }
}
if ($Ref -cnotmatch '^[A-Za-z0-9._/-]+$' -or $Ref.StartsWith('/') -or $Ref -match '(^|/)\.\.(/|$)') { Fail 'invalid ref' }
$Url = if ($Ref -ceq 'main') { "$Repository/archive/refs/heads/main.zip" } else { "$Repository/archive/$Ref.zip" }
$TempRoot = Join-Path ([IO.Path]::GetTempPath()) ('llm-sast-bootstrap.' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($TempRoot)
try {
    $archive = Join-Path $TempRoot 'source.zip'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    try { Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $archive } catch { Fail "download failed: $($_.Exception.Message)" }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $destination = Join-Path $TempRoot 'extracted'
    [void][IO.Directory]::CreateDirectory($destination)
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    $root = $null
    try {
        if ($zip.Entries.Count -eq 0 -or $zip.Entries.Count -gt 50000) { Fail 'invalid archive entry count' }
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.TrimEnd('/')
            if ([string]::IsNullOrEmpty($name) -or $name.Length -gt 500 -or $name.Contains('\') -or $name.Contains('//') -or $name -match '[\x00-\x1f]') { Fail "unsafe archive path: $name" }
            $parts = @($name.Split('/'))
            if ($parts -contains '..' -or $parts -contains '.') { Fail "unsafe archive path: $name" }
            if ($null -eq $root) { $root = $parts[0] }
            if ($parts[0] -cne $root -or $root -cnotmatch '^llm-sast-scanner-.+$') { Fail 'archive has an invalid or multiple root' }
            $unixType = (($entry.ExternalAttributes -shr 16) -band 61440)
            if ($unixType -notin @(0, 16384, 32768, 40960)) { Fail "archive contains an unsupported entry type: $name" }
            $relative = if ($parts.Count -gt 1) { [string]::Join('/', $parts[1..($parts.Count - 1)]) } else { '' }
            $needed = $relative -ceq 'install.ps1' -or $relative -match '^(llm-sast-scanner|llm-sast-scanner-convergence-loop|llm-sast-scanner-full-scan-loop)(/|$)'
            if (-not $needed) { continue }
            if ($unixType -eq 40960) { Fail "required source contains a link: $name" }
            $target = [IO.Path]::GetFullPath((Join-Path $destination $entry.FullName))
            $prefix = [IO.Path]::GetFullPath($destination).TrimEnd('\') + '\'
            if (-not $target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { Fail "unsafe archive path: $name" }
            if ($entry.FullName.EndsWith('/')) { [void][IO.Directory]::CreateDirectory($target); continue }
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
            $input = $entry.Open(); $output = [IO.File]::Create($target)
            try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
        }
    } finally { $zip.Dispose() }
    $source = Join-Path $destination $root
    $installer = Join-Path $source 'install.ps1'
    if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { Fail 'archive is missing install.ps1' }
    foreach ($skill in @('llm-sast-scanner', 'llm-sast-scanner-convergence-loop', 'llm-sast-scanner-full-scan-loop')) {
        if (-not (Test-Path -LiteralPath (Join-Path $source "$skill\SKILL.md") -PathType Leaf)) { Fail "archive is missing required skill: $skill" }
    }
    & $installer @Forward
    exit 0
} finally { Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue }
