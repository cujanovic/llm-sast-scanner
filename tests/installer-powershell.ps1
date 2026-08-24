Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$TestRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo = [IO.Path]::GetFullPath((Join-Path $TestRoot '..'))
$PowerShell = (Get-Process -Id $PID).Path
$Skills = @('llm-sast-scanner', 'llm-sast-scanner-convergence-loop', 'llm-sast-scanner-full-scan-loop')
$Marker = '.llm-sast-scanner-managed'
$MarkerText = 'llm-sast-scanner-managed-v1'
$Pass = 0; $Fail = 0; $Sandbox = $null; $Status = 0; $Output = ''

function Assert([bool] $Condition, [string] $Message) { if (-not $Condition) { throw "assertion failed: $Message" } }
function New-Sandbox {
    if ($null -ne $script:Sandbox) { Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue }
    $script:Sandbox = Join-Path ([IO.Path]::GetTempPath()) ('llm sast tests ' + [Guid]::NewGuid().ToString('N'))
    $home = Join-Path $Sandbox 'home with spaces'; $temp = Join-Path $Sandbox 'temp'; $source = Join-Path $Sandbox 'source with spaces'
    foreach ($path in @($home, $temp, $source)) { [void][IO.Directory]::CreateDirectory($path) }
    $env:USERPROFILE = $home; $env:HOME = $home; $env:APPDATA = Join-Path $home 'AppData\Roaming'; $env:TEMP = $temp; $env:TMP = $temp
    Copy-Item -LiteralPath (Join-Path $Repo 'install.ps1') -Destination (Join-Path $source 'install.ps1')
    foreach ($skill in $Skills) { $path = Join-Path $source $skill; [void][IO.Directory]::CreateDirectory($path); [IO.File]::WriteAllText((Join-Path $path 'SKILL.md'), "# fixture`nold`n") }
    $script:Source = $source; $script:Installer = Join-Path $source 'install.ps1'
}
function Invoke-File([string] $File, [string[]] $Arguments) {
    $stdout = Join-Path $Sandbox ('out-' + [Guid]::NewGuid().ToString('N')); $stderr = "$stdout.err"
    $all = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $File) + $Arguments
    $quoted = @($all | ForEach-Object { '"' + ([string]$_).Replace('"', '\"') + '"' })
    $process = Start-Process -FilePath $PowerShell -ArgumentList ([string]::Join(' ', $quoted)) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $script:Status = $process.ExitCode; $script:Output = ((Get-Content -LiteralPath $stdout, $stderr -Raw -ErrorAction SilentlyContinue) -join '').Trim()
    Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
}
function Run([string[]] $Arguments) { Invoke-File $Installer $Arguments }
function Test-Case([string] $Name, [scriptblock] $Body) {
    try { & $Body; $script:Pass++; Write-Output "ok - $Name" } catch { $script:Fail++; [Console]::Error.WriteLine("not ok - $Name`: $($_.Exception.Message)") }
}

Test-Case 'global/project destinations, dedup, spaces' {
    New-Sandbox; Run @('install', '--runtime', 'all', '--yes'); Assert ($Status -eq 0) $Output
    foreach ($root in @((Join-Path $env:USERPROFILE '.claude\skills'), (Join-Path $env:USERPROFILE '.agents\skills'))) { foreach ($skill in $Skills) {
        Assert (Test-Path -LiteralPath (Join-Path $root "$skill\SKILL.md") -PathType Leaf) "missing $root/$skill"
        $markerPath = Join-Path $root "$skill\$Marker"
        Assert (Test-Path -LiteralPath $markerPath -PathType Leaf) 'missing marker'
        Assert ([IO.File]::ReadAllText($markerPath).TrimEnd([char[]]"`r`n") -ceq "$MarkerText`:$skill") 'wrong marker content'
    }}
    Assert (-not (Test-Path -LiteralPath (Join-Path $env:APPDATA 'devin\skills'))) 'agents+devin were not deduplicated'
    $project = Join-Path $Sandbox 'project path with spaces'; [void][IO.Directory]::CreateDirectory($project)
    Run @('--project', $project, '--runtime', 'devin'); Assert ($Status -eq 0) $Output
    Assert (Test-Path -LiteralPath (Join-Path $project '.devin\skills\llm-sast-scanner\SKILL.md')) 'missing project copy'
}
Test-Case 'unmanaged conflict and legacy migration' {
    New-Sandbox; $root = Join-Path $env:USERPROFILE '.agents\skills'; $conflict = Join-Path $root 'llm-sast-scanner'
    [void][IO.Directory]::CreateDirectory($conflict); [IO.File]::WriteAllText((Join-Path $conflict 'file'), 'unrelated')
    Run @('--runtime', 'agents'); Assert ($Status -ne 0 -and $Output.Contains('unmanaged')) 'unmanaged path accepted'
    Remove-Item -LiteralPath (Join-Path $env:USERPROFILE '.agents') -Recurse -Force
    $legacy = Join-Path $Sandbox 'legacy'; [void][IO.Directory]::CreateDirectory($root); [void][IO.Directory]::CreateDirectory($legacy)
    foreach ($skill in $Skills) {
        $target = Join-Path $legacy $skill; [void][IO.Directory]::CreateDirectory($target); [IO.File]::WriteAllText((Join-Path $target 'SKILL.md'), 'legacy')
        $link = Join-Path $root $skill; $null = & cmd.exe /c "mklink /J `"$link`" `"$target`"" 2>&1; Assert ($LASTEXITCODE -eq 0) 'could not create legacy junction'
    }
    Run @('--runtime', 'agents'); Assert ($Status -ne 0 -and $Output.Contains('requires --yes')) 'legacy migration did not require yes'
    Run @('--runtime', 'agents', '--yes'); Assert ($Status -eq 0) $Output
    Assert (Test-Path -LiteralPath (Join-Path $root "llm-sast-scanner\$Marker")) 'legacy migration failed'
}
Test-Case 'rerun update, doctor, dry-run, uninstall' {
    New-Sandbox; Run @('--runtime', 'agents'); Assert ($Status -eq 0) $Output
    Run @('--runtime', 'agents', '--quiet'); Assert ($Status -eq 0 -and $Output -eq '') 'quiet rerun failed'
    [IO.File]::WriteAllText((Join-Path $Source 'llm-sast-scanner\SKILL.md'), "# fixture`nnew`n")
    Run @('install', '--runtime', 'agents'); Assert ($Status -eq 0) $Output
    Assert ([IO.File]::ReadAllText((Join-Path $env:USERPROFILE '.agents\skills\llm-sast-scanner\SKILL.md')).Contains('new')) 'rerun did not update'
    Run @('doctor', '--runtime', 'agents'); Assert ($Status -eq 0 -and $Output.Contains('ok:')) 'doctor failed'
    Run @('uninstall', '--runtime', 'agents', '--dry-run'); Assert ($Status -eq 0) 'dry uninstall failed'
    Assert (Test-Path -LiteralPath (Join-Path $env:USERPROFILE '.agents\skills\llm-sast-scanner')) 'dry-run wrote files'
    Run @('uninstall', '--runtime', 'agents'); Assert ($Status -eq 0) $Output
}
Test-Case 'doctor and safe uninstall' {
    New-Sandbox; Run @('--runtime', 'claude'); Assert ($Status -eq 0) $Output
    $path = Join-Path $env:USERPROFILE '.claude\skills\llm-sast-scanner'; Remove-Item -LiteralPath (Join-Path $path $Marker)
    Run @('doctor', '--runtime', 'claude'); Assert ($Status -ne 0) 'doctor accepted missing marker'
    Run @('uninstall', '--runtime', 'claude'); Assert ($Status -ne 0 -and (Test-Path -LiteralPath $path)) 'unsafe uninstall removed copy'
}
Test-Case 'forged marker refusal' {
    New-Sandbox; Run @('--runtime', 'agents'); Assert ($Status -eq 0) $Output
    $path = Join-Path $env:USERPROFILE '.agents\skills\llm-sast-scanner'; $markerPath = Join-Path $path $Marker
    foreach ($content in @($MarkerText, "$MarkerText`:llm-sast-scanner-convergence-loop")) {
        [IO.File]::WriteAllText($markerPath, $content + [Environment]::NewLine)
        Run @('doctor', '--runtime', 'agents'); Assert ($Status -ne 0) 'doctor accepted forged marker'
        Run @('install', '--runtime', 'agents'); Assert ($Status -ne 0 -and $Output.Contains('unmanaged')) 'reinstall accepted forged marker'
        Run @('uninstall', '--runtime', 'agents'); Assert ($Status -ne 0 -and (Test-Path -LiteralPath $path)) 'uninstall accepted forged marker'
    }
}
Test-Case 'install dry-run' {
    New-Sandbox; Run @('--runtime', 'agents', '--dry-run'); Assert ($Status -eq 0 -and $Output.Contains('would install')) 'dry-run failed'
    Assert (-not (Test-Path -LiteralPath (Join-Path $env:USERPROFILE '.agents'))) 'dry-run changed home'
}
Test-Case 'mocked bootstrap' {
    New-Sandbox; Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archiveParent = Join-Path $Sandbox 'archive'; $archiveRoot = Join-Path $archiveParent 'llm-sast-scanner-main'; [void][IO.Directory]::CreateDirectory($archiveRoot)
    Copy-Item -LiteralPath (Join-Path $Source 'install.ps1') -Destination $archiveRoot
    foreach ($skill in $Skills) { Copy-Item -LiteralPath (Join-Path $Source $skill) -Destination $archiveRoot -Recurse }
    $archive = Join-Path $Sandbox 'source.zip'; [IO.Compression.ZipFile]::CreateFromDirectory($archiveParent, $archive)
    $wrapper = Join-Path $Sandbox 'mock-bootstrap.ps1'; $env:MOCK_ARCHIVE = $archive
    $bootstrap = (Join-Path $Repo 'bootstrap.ps1').Replace("'", "''")
    [IO.File]::WriteAllText($wrapper, "function Invoke-WebRequest { param([switch]`$UseBasicParsing,[string]`$Uri,[string]`$OutFile) Copy-Item -LiteralPath `$env:MOCK_ARCHIVE -Destination `$OutFile }`n& '$bootstrap' @args`nexit `$LASTEXITCODE`n")
    Invoke-File $wrapper @('--runtime', 'agents'); Assert ($Status -eq 0) $Output
    Assert (Test-Path -LiteralPath (Join-Path $env:USERPROFILE ".agents\skills\llm-sast-scanner\$Marker")) 'bootstrap did not install'
}

if ($null -ne $Sandbox) { Remove-Item -LiteralPath $Sandbox -Recurse -Force -ErrorAction SilentlyContinue }
Write-Output "$Pass passed, $Fail failed"
if ($Fail -ne 0) { exit 1 }
