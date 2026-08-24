Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Program = 'llm-sast-scanner-installer'
$Marker = '.llm-sast-scanner-managed'
$MarkerText = 'llm-sast-scanner-managed-v1'
$Skills = @('llm-sast-scanner', 'llm-sast-scanner-convergence-loop', 'llm-sast-scanner-full-scan-loop')
$Command = 'install'
$Project = $null
$Yes = $false
$DryRun = $false
$Quiet = $false
$Runtimes = New-Object Collections.Generic.List[string]
$commandSet = $false

function Fail([string] $Message) { [Console]::Error.WriteLine("$Program`: error: $Message"); exit 1 }
function Say([string] $Message) { if (-not $Quiet) { [Console]::Out.WriteLine($Message) } }
function Usage {
@'
Usage: install.ps1 [install|doctor|uninstall] [options]

Options:
  --project PATH       Use project-local runtime directories
  --runtime NAME       Select claude, agents, devin, or all (repeatable)
  --yes                Non-interactive selection and legacy-link migration
  --dry-run            Show changes without writing them
  --quiet              Suppress normal output
  -h, --help           Show this help

Run install again to update managed copies.
'@ | Write-Output
}
function Add-Runtime([string] $Name) {
    if ($Name -ceq 'all') { Add-Runtime claude; Add-Runtime agents; Add-Runtime devin; return }
    if ($Name -cnotin @('claude', 'agents', 'devin')) { Fail "unknown runtime: $Name" }
    if (-not $Runtimes.Contains($Name)) { [void]$Runtimes.Add($Name) }
}

$arguments = @($args)
for ($index = 0; $index -lt $arguments.Count; $index++) {
    $argument = [string]$arguments[$index]
    if ($argument -cin @('install', 'doctor', 'uninstall')) {
        if ($commandSet) { Fail 'only one command may be specified' }
        $Command = $argument; $commandSet = $true
    } elseif ($argument -ceq '--project') {
        if (++$index -ge $arguments.Count) { Fail '--project requires PATH' }
        $Project = [string]$arguments[$index]
    } elseif ($argument -ceq '--runtime') {
        if (++$index -ge $arguments.Count) { Fail '--runtime requires NAME' }
        Add-Runtime ([string]$arguments[$index])
    } elseif ($argument -ceq '--yes') { $Yes = $true
    } elseif ($argument -ceq '--dry-run') { $DryRun = $true
    } elseif ($argument -ceq '--quiet') { $Quiet = $true
    } elseif ($argument -cin @('-h', '--help')) { Usage; exit 0
    } else { Fail "unknown argument: $argument" }
}

$Source = $PSScriptRoot
foreach ($skill in $Skills) {
    if (-not (Test-Path -LiteralPath (Join-Path $Source "$skill\SKILL.md") -PathType Leaf)) { Fail "missing source skill: $(Join-Path $Source $skill)" }
}
if ([string]::IsNullOrEmpty($env:USERPROFILE)) { Fail 'USERPROFILE is not set' }
if ($null -ne $Project) {
    if (-not (Test-Path -LiteralPath $Project -PathType Container)) { Fail "project path is not a directory: $Project" }
    $Project = [IO.Path]::GetFullPath($Project)
}
function Runtime-Root([string] $Runtime) {
    if ($null -ne $Project) {
        if ($Runtime -ceq 'claude') { return Join-Path $Project '.claude\skills' }
        if ($Runtime -ceq 'agents') { return Join-Path $Project '.agents\skills' }
        return Join-Path $Project '.devin\skills'
    }
    if ($Runtime -ceq 'claude') { return Join-Path $env:USERPROFILE '.claude\skills' }
    if ($Runtime -ceq 'agents') { return Join-Path $env:USERPROFILE '.agents\skills' }
    $appData = if ([string]::IsNullOrEmpty($env:APPDATA)) { Join-Path $env:USERPROFILE 'AppData\Roaming' } else { $env:APPDATA }
    return Join-Path $appData 'devin\skills'
}
if ($Runtimes.Count -eq 0) {
    if ($Yes) { Add-Runtime all }
    elseif (-not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected) {
        $detected = @(@('claude', 'agents', 'devin') | Where-Object { Test-Path -LiteralPath (Runtime-Root $_) -PathType Container })
        if ($detected.Count -eq 0) { $detected = @('claude', 'agents', 'devin') }
        $answer = Read-Host "Install for $([string]::Join(', ', $detected))? [Y/n]"
        if ($answer -notin @('', 'y', 'Y', 'yes', 'YES')) { Fail 'installation cancelled' }
        foreach ($runtime in $detected) { Add-Runtime $runtime }
    } else { Fail 'non-interactive use requires --runtime NAME or --yes' }
}
if ($Runtimes.Contains('agents') -and $Runtimes.Contains('devin')) { [void]$Runtimes.Remove('devin') }

function Is-Managed([string] $Path, [string] $Skill) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
    $directory = Get-Item -LiteralPath $Path -Force
    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    $markerPath = Join-Path $Path $Marker
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { return $false }
    $item = Get-Item -LiteralPath $markerPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    return ([IO.File]::ReadAllText($markerPath).TrimEnd([char[]]"`r`n") -ceq "$MarkerText`:$Skill")
}
function Is-Legacy([string] $Path, [string] $Skill) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { return $false }
    try {
        $rawTarget = [string]$item.Target
        $target = if ([IO.Path]::IsPathRooted($rawTarget)) { [IO.Path]::GetFullPath($rawTarget) } else { [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $Path) $rawTarget)) }
    } catch { return $false }
    return ((Split-Path -Leaf $target) -ceq $Skill -and (Test-Path -LiteralPath (Join-Path $target 'SKILL.md') -PathType Leaf))
}
function Check-Destination([string] $Path, [string] $Skill) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        if (-not (Is-Legacy $Path $Skill)) { Fail "refusing unmanaged link: $Path" }
        if (-not $Yes) { Fail "legacy link requires --yes: $Path" }
    } elseif (-not (Is-Managed $Path $Skill)) { Fail "refusing unmanaged path: $Path" }
}

if ($Command -ceq 'doctor') {
    $bad = $false
    foreach ($runtime in $Runtimes) { foreach ($skill in $Skills) {
        $destination = Join-Path (Runtime-Root $runtime) $skill
        if ((Is-Managed $destination $skill) -and (Test-Path -LiteralPath (Join-Path $destination 'SKILL.md') -PathType Leaf)) { Say "ok: $destination" }
        else { [Console]::Error.WriteLine("invalid or missing: $destination"); $bad = $true }
    }}
    if ($bad) { exit 1 }; exit 0
}
if ($Command -ceq 'uninstall') {
    foreach ($runtime in $Runtimes) { foreach ($skill in $Skills) {
        $destination = Join-Path (Runtime-Root $runtime) $skill
        if (Test-Path -LiteralPath $destination) {
            if (-not (Is-Managed $destination $skill)) { Fail "refusing unmanaged path: $destination" }
            if ($DryRun) { Say "would remove $destination" } else { Remove-Item -LiteralPath $destination -Recurse -Force; Say "removed $destination" }
        }
    }}
    exit 0
}

foreach ($runtime in $Runtimes) { foreach ($skill in $Skills) { Check-Destination (Join-Path (Runtime-Root $runtime) $skill) $skill } }
if ($DryRun) {
    foreach ($runtime in $Runtimes) { foreach ($skill in $Skills) { Say "would install $(Join-Path (Runtime-Root $runtime) $skill)" } }
    exit 0
}

$plan = New-Object Collections.Generic.List[object]
$activated = New-Object Collections.Generic.List[object]
try {
    $index = 0
    foreach ($runtime in $Runtimes) {
        $root = Runtime-Root $runtime
        [void][IO.Directory]::CreateDirectory($root)
        foreach ($skill in $Skills) {
            $index++; $stage = Join-Path $root ".llm-sast-stage-$PID-$index"; $destination = Join-Path $root $skill
            $backup = if (Test-Path -LiteralPath $destination) { Join-Path $root ".llm-sast-backup-$PID-$index" } else { $null }
            [void]$plan.Add([pscustomobject]@{ Stage=$stage; Destination=$destination; Backup=$backup })
            if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
            [void][IO.Directory]::CreateDirectory($stage)
            Get-ChildItem -LiteralPath (Join-Path $Source $skill) -Force | Copy-Item -Destination $stage -Recurse -Force
            [IO.File]::WriteAllText((Join-Path $stage $Marker), "$MarkerText`:$skill" + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        }
    }
    foreach ($entry in $plan) {
        if ($null -ne $entry.Backup) { Move-Item -LiteralPath $entry.Destination -Destination $entry.Backup }
        [void]$activated.Add($entry)
        Move-Item -LiteralPath $entry.Stage -Destination $entry.Destination
    }
} catch {
    for ($index = $activated.Count - 1; $index -ge 0; $index--) {
        $entry = $activated[$index]
        if (Test-Path -LiteralPath $entry.Destination) { Remove-Item -LiteralPath $entry.Destination -Recurse -Force }
        if ($null -ne $entry.Backup -and (Test-Path -LiteralPath $entry.Backup)) { Move-Item -LiteralPath $entry.Backup -Destination $entry.Destination }
    }
    foreach ($entry in $plan) { if (Test-Path -LiteralPath $entry.Stage) { Remove-Item -LiteralPath $entry.Stage -Recurse -Force } }
    Fail "activation failed; previous installation restored: $($_.Exception.Message)"
}
foreach ($entry in $plan) {
    if ($null -ne $entry.Backup -and (Test-Path -LiteralPath $entry.Backup)) { Remove-Item -LiteralPath $entry.Backup -Recurse -Force }
    Say "installed $($entry.Destination)"
}
