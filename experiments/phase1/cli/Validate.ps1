[CmdletBinding()]
param([ValidateRange(30, 300)][int] $CommandTimeoutSeconds = 180)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath("$PSScriptRoot/../../..").Replace([char]92, [char]47)
$targetRoot = "$repoRoot/target"
$fixture = "$targetRoot/cli-validation-$([guid]::NewGuid().ToString('N'))"
$resultRoot = "$PSScriptRoot/results"
[IO.Directory]::CreateDirectory($resultRoot) | Out-Null
$resultPath = "$resultRoot/61-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()).json"
$checks = [Collections.Generic.List[object]]::new()
$cleanup = 'Not Tested'
$artifact = $null

function Get-Inputs {
    $hashes = [ordered]@{}
    $paths = @('Cargo.toml', 'Cargo.lock', 'crates/sentra-core/Cargo.toml', 'crates/sentra-cli/Cargo.toml', 'experiments/phase1/cli/Validate.ps1', 'experiments/phase1/authorization/Validate.ps1') +
        @(Get-ChildItem -LiteralPath "$repoRoot/crates" -Recurse -File | Where-Object { $_.Extension -in @('.rs', '.sql') } | Sort-Object FullName | ForEach-Object { [IO.Path]::GetRelativePath($repoRoot, $_.FullName).Replace([char]92, [char]47) })
    foreach ($path in $paths) { $hashes[$path] = (Get-FileHash -LiteralPath "$repoRoot/$path" -Algorithm SHA256).Hash.ToLowerInvariant() }
    return $hashes
}

function Invoke-Recorded {
    param([string] $Name, [string] $Executable, [string[]] $Arguments, [string] $WorkingDirectory = $repoRoot, [int] $ExpectedExit = 0)
    $process = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = (Get-Command $Executable -CommandType Application).Source
        $start.WorkingDirectory = $WorkingDirectory
        $start.CreateNoWindow = $true
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.Environment['CARGO_NET_OFFLINE'] = 'true'
        foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        if (-not $process.Start()) { throw 'Validation process did not start' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($CommandTimeoutSeconds * 1000)
        if ($timedOut) { $process.Kill($true); $process.WaitForExit() }
        $output = $stdout.GetAwaiter().GetResult()
        Write-Host "$Name exit=$($process.ExitCode) expected=$ExpectedExit timed_out=$timedOut"
        return [ordered]@{ name = $Name; executable = $start.FileName.Replace([char]92, [char]47); arguments = $Arguments; working_directory = $WorkingDirectory
            status = $(if (-not $timedOut -and $process.ExitCode -eq $ExpectedExit) { 'Passed' } else { 'Failed' })
            exit_code = $process.ExitCode; expected_exit = $ExpectedExit; timed_out = $timedOut; elapsed_ms = $timer.ElapsedMilliseconds
            stdout = $output; stderr = $stderr.GetAwaiter().GetResult()
            tests = @([regex]::Matches($output, '(?m)^test (?<name>.+?) \.\.\. (?<outcome>ok|FAILED|ignored)') | ForEach-Object { [ordered]@{ name = $_.Groups['name'].Value; outcome = $_.Groups['outcome'].Value } })
            summaries = @([regex]::Matches($output, 'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;') | ForEach-Object { [ordered]@{ passed = [int]$_.Groups[1].Value; failed = [int]$_.Groups[2].Value; ignored = [int]$_.Groups[3].Value } }) }
    }
    catch { return [ordered]@{ name = $Name; status = 'Blocked'; exit_code = $null; stdout = ''; stderr = $_.Exception.Message; tests = @(); summaries = @() } }
    finally { if ($process) { $process.Dispose() } }
}

function Remove-OwnedFixture {
    param([string] $Path)
    $full = [IO.Path]::GetFullPath($Path).Replace([char]92, [char]47)
    if ($full -ne $fixture -and -not $full.StartsWith("$fixture/", [StringComparison]::OrdinalIgnoreCase)) { throw 'Cleanup escaped the owned CLI fixture' }
    $attributes = [IO.File]::GetAttributes($full)
    $directory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        if ($directory) { [IO.Directory]::Delete($full) } else { [IO.File]::Delete($full) }
    }
    elseif ($directory) {
        foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($full)) { Remove-OwnedFixture $child }
        [IO.Directory]::Delete($full)
    }
    else { [IO.File]::Delete($full) }
}

$inputs = Get-Inputs
try {
    $checks.Add((Invoke-Recorded 'rust-version' 'rustc' @('-vV')))
    $checks.Add((Invoke-Recorded 'cargo-version' 'cargo' @('--version')))
    $checks.Add((Invoke-Recorded 'format' 'cargo' @('fmt', '--all', '--', '--check')))
    $checks.Add((Invoke-Recorded 'check' 'cargo' @('check', '--workspace', '--all-targets', '--all-features', '--offline')))
    $checks.Add((Invoke-Recorded 'clippy' 'cargo' @('clippy', '--workspace', '--all-targets', '--all-features', '--offline', '--', '-D', 'warnings')))
    $checks.Add((Invoke-Recorded 'workspace-tests' 'cargo' @('test', '--workspace', '--offline')))
    $checks.Add((Invoke-Recorded 'discovered-tests' 'cargo' @('test', '--workspace', '--offline', '--', '--list')))
    $checks.Add((Invoke-Recorded 'dependency-tree' 'cargo' @('tree', '--workspace', '--offline', '-e', 'features')))
    $metadata = Invoke-Recorded 'metadata' 'cargo' @('metadata', '--offline', '--no-deps', '--format-version', '1')
    $checks.Add($metadata)
    $build = Invoke-Recorded 'cli-build-artifact' 'cargo' @('build', '--offline', '--package', 'sentra-cli', '--message-format=json')
    $checks.Add($build)
    if ($build.status -eq 'Passed' -and $metadata.status -eq 'Passed') {
        $target = [IO.Path]::GetFullPath(($metadata.stdout | ConvertFrom-Json).target_directory)
        $executables = @($build.stdout -split "`n" | Where-Object { $_.StartsWith('{') } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'sentra' -and $null -ne $_.executable } | ForEach-Object { $_.executable })
        if ($executables.Count -ne 1) { throw 'Expected exactly one CLI executable for this invocation' }
        $artifact = [IO.Path]::GetFullPath($executables[0]).Replace([char]92, [char]47)
        $relative = [IO.Path]::GetRelativePath($target, $artifact)
        if ([IO.Path]::IsPathRooted($relative) -or ($relative -split '[/\\]')[0] -eq '..' -or -not [IO.File]::Exists($artifact)) { throw 'CLI artifact escaped the actual Cargo target directory' }
        if (-not [IO.Path]::GetFullPath($fixture).Replace([char]92, [char]47).StartsWith("$targetRoot/", [StringComparison]::OrdinalIgnoreCase)) { throw 'Fixture escaped target' }
        [IO.Directory]::CreateDirectory("$fixture/workspace Unicode ü space") | Out-Null
        [IO.Directory]::CreateDirectory("$fixture/storage") | Out-Null
        $workspace = "$fixture/workspace Unicode ü space"
        $database = "$fixture/storage/local.db"
        $checks.Add((Invoke-Recorded 'json-uninitialized' $artifact @('status', '--workspace', $workspace, '--database', $database, '--json') $repoRoot 3))
        $init = Invoke-Recorded 'json-init' $artifact @('init', '--workspace', $workspace, '--database', $database, '--json')
        $checks.Add($init)
        $initialized = $init.stdout | ConvertFrom-Json
        $repeat = Invoke-Recorded 'json-repeat-init' $artifact @('init', '--workspace', $workspace, '--database', $database, '--json')
        $checks.Add($repeat)
        $repeated = $repeat.stdout | ConvertFrom-Json
        if (-not $initialized.created -or $repeated.created -or $initialized.session_id -ne $repeated.session_id -or $initialized.project_id -ne $repeated.project_id -or $initialized.untrusted_execution) { throw 'CLI JSON identity/lifecycle contract failed' }
        $status = Invoke-Recorded 'json-status-from-workspace' $artifact @('status', '--database', $database, '--json') $workspace
        $checks.Add($status)
        $inspected = $status.stdout | ConvertFrom-Json
        if (-not $inspected.initialized -or $inspected.session_id -ne $initialized.session_id) { throw 'Status JSON contract failed' }
        $session = Invoke-Recorded 'json-session' $artifact @('session', 'show', $initialized.session_id, '--database', $database, '--json') $workspace
        $checks.Add($session)
        if (($session.stdout | ConvertFrom-Json).session_id -ne $initialized.session_id) { throw 'Session JSON contract failed' }
        $invalid = Invoke-Recorded 'json-invalid-arguments' $artifact @('scan', '--json') $repoRoot 2
        $checks.Add($invalid)
        if (($invalid.stderr | ConvertFrom-Json).error -ne 'invalid_arguments') { throw 'Error JSON contract failed' }
        if ($IsWindows) {
            New-Item -ItemType Junction -Path "$fixture/root-junction" -Target $workspace | Out-Null
            New-Item -ItemType Junction -Path "$fixture/storage-junction" -Target "$fixture/storage" | Out-Null
            $checks.Add((Invoke-Recorded 'windows-junction-root' $artifact @('init', '--workspace', "$fixture/root-junction", '--database', "$fixture/storage/forbidden.db", '--json') $repoRoot 4))
            $checks.Add((Invoke-Recorded 'windows-junction-storage' $artifact @('init', '--workspace', $workspace, '--database', "$fixture/storage-junction/forbidden.db", '--json') $repoRoot 4))
            if ([IO.File]::Exists("$fixture/storage/forbidden.db")) { throw 'Junction rejection modified storage' }
        }
        else { $checks.Add([ordered]@{ name = 'windows-junctions'; status = 'Not Tested'; stdout = ''; stderr = 'Windows platform required'; tests = @(); summaries = @() }) }
    }
}
catch { $checks.Add([ordered]@{ name = 'validation-driver'; status = 'Blocked'; exit_code = $null; stdout = ''; stderr = $_.Exception.Message; tests = @(); summaries = @() }) }
finally {
    try { if ([IO.Directory]::Exists($fixture)) { Remove-OwnedFixture $fixture }; $cleanup = 'Passed' }
    catch { $cleanup = 'Failed'; $checks.Add([ordered]@{ name = 'fixture-cleanup'; status = 'Failed'; stdout = ''; stderr = $_.Exception.Message; tests = @(); summaries = @() }) }
}
$stable = ($inputs | ConvertTo-Json -Compress) -ceq ((Get-Inputs) | ConvertTo-Json -Compress)
$report = [ordered]@{
    increment = '6.1 local CLI foundation'; observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    inputs_unchanged = $stable; input_sha256 = $inputs; artifact = $artifact; fixture_cleanup = $cleanup
    environment = [ordered]@{ powershell = $PSVersionTable.PSVersion.ToString(); os = [Runtime.InteropServices.RuntimeInformation]::OSDescription; architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString(); cargo_target_dir = $env:CARGO_TARGET_DIR }
    command_timeout_seconds = $CommandTimeoutSeconds; checks = $checks.ToArray()
    note = 'Cargo workspace output is the unique-case inventory. CLI subprocess smoke checks and overlapping validators are additional executions, not new Rust cases. No target workload or external service.'
}
[IO.File]::WriteAllText($resultPath, ($report | ConvertTo-Json -Depth 25) + "`n", [Text.UTF8Encoding]::new($false))
$checks | ForEach-Object { [PSCustomObject]@{ Name = $_.name; Status = $_.status; Exit = $_.exit_code } } | Format-Table -AutoSize
Write-Output "Evidence: $resultPath"
if (-not $stable -or $cleanup -ne 'Passed' -or @($checks | Where-Object { $_.status -ne 'Passed' }).Count -gt 0) { exit 1 }
