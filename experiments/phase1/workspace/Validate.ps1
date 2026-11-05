[CmdletBinding()]
param([ValidateRange(1, 60)][int] $CommandTimeoutSeconds = 60)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath("$PSScriptRoot/../../..").Replace([char]92, [char]47)
$targetRoot = "$repoRoot/target"
$ownedFixture = "$targetRoot/workspace-validation-$([guid]::NewGuid().ToString('N'))"
if (-not [IO.Path]::GetFullPath($ownedFixture).Replace([char]92, [char]47).StartsWith("$targetRoot/", [StringComparison]::OrdinalIgnoreCase)) { throw 'Fixture root escaped target directory' }
$resultRoot = "$PSScriptRoot/results"
[IO.Directory]::CreateDirectory($resultRoot) | Out-Null
$resultPath = "$resultRoot/$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()).json"
$checks = [Collections.Generic.List[object]]::new()
$fixtureChecks = [Collections.Generic.List[object]]::new()
$savedAcls = [Collections.Generic.List[object]]::new()
$cleanupStatus = 'Not Tested'

function Get-InputHashes {
    $hashes = [ordered]@{}
    $paths = @('Cargo.toml', 'Cargo.lock', 'crates/sentra-core/Cargo.toml', 'experiments/phase1/workspace/Validate.ps1') + @(Get-ChildItem -LiteralPath "$repoRoot/crates/sentra-core" -Filter '*.rs' -Recurse -File | ForEach-Object { [IO.Path]::GetRelativePath($repoRoot, $_.FullName).Replace([char]92, [char]47) })
    foreach ($path in $paths) { $hashes[$path] = (Get-FileHash -LiteralPath "$repoRoot/$path" -Algorithm SHA256).Hash.ToLowerInvariant() }
    return $hashes
}
$inputs = Get-InputHashes

function Invoke-Recorded {
    param([string] $Name, [string] $Executable, [string[]] $Arguments)
    $process = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $resolved = (Get-Command $Executable -CommandType Application -ErrorAction Stop).Source
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $resolved
        $start.WorkingDirectory = $repoRoot
        $start.CreateNoWindow = $true
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.Environment['CARGO_NET_OFFLINE'] = 'true'
        $start.Environment['CARGO_TERM_COLOR'] = 'never'
        $start.Environment['SENTRA_WORKSPACE_TEST_FIXTURE'] = $ownedFixture
        foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        if (-not $process.Start()) { throw 'Process did not start' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $peakMemory = 0L
        while (-not $process.WaitForExit(25) -and $timer.Elapsed.TotalSeconds -lt $CommandTimeoutSeconds) {
            try { $process.Refresh(); $peakMemory = [Math]::Max($peakMemory, $process.get_PeakWorkingSet64()) } catch { }
        }
        $timedOut = -not $process.HasExited
        if ($timedOut) { $process.Kill($true); $process.WaitForExit() }
        $timer.Stop()
        Write-Host "$Name exit=$($process.ExitCode) timed_out=$timedOut"
        [ordered]@{ name = $Name; executable = $resolved.Replace([char]92, [char]47); arguments = $Arguments
            status = $(if ($process.ExitCode -eq 0 -and -not $timedOut) { 'Passed' } else { 'Failed' })
            exit_code = $process.ExitCode; timed_out = $timedOut; elapsed_ms = $timer.ElapsedMilliseconds
            peak_working_set_bytes = $(if ($peakMemory -gt 0) { $peakMemory } else { $null })
            stdout = $stdout.GetAwaiter().GetResult(); stderr = $stderr.GetAwaiter().GetResult() }
    }
    catch { [ordered]@{ name = $Name; executable = $Executable; arguments = $Arguments; status = 'Blocked'; exit_code = $null; timed_out = $false; elapsed_ms = $timer.ElapsedMilliseconds; peak_working_set_bytes = $null; stdout = ''; stderr = $_.Exception.Message } }
    finally { if ($process) { $process.Dispose() } }
}

# Safe cleanup of this exact owned tree. Reparse directories are unlinked themselves.
function Remove-OwnedFixture {
    param([string] $Path)
    $full = [IO.Path]::GetFullPath($Path).Replace([char]92, [char]47)
    if ($full -ne $ownedFixture -and -not $full.StartsWith("$ownedFixture/", [StringComparison]::OrdinalIgnoreCase)) { throw 'Cleanup escaped the owned fixture' }
    $attributes = [IO.File]::GetAttributes($full)
    $isDirectory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        if ($isDirectory) { [IO.Directory]::Delete($full) } else { [IO.File]::Delete($full) }
    }
    elseif ($isDirectory) {
        foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($full)) { Remove-OwnedFixture $child }
        [IO.Directory]::Delete($full)
    }
    else { [IO.File]::Delete($full) }
}

try {
    [IO.Directory]::CreateDirectory("$ownedFixture/outside") | Out-Null
    [IO.File]::WriteAllText("$ownedFixture/outside/HOST_CANARY", 'synthetic outside fixture')
    [IO.Directory]::CreateDirectory("$ownedFixture/junction-repo/.git") | Out-Null
    [IO.File]::WriteAllText("$ownedFixture/junction-repo/.git/INTERNAL_CANARY", 'opaque internal fixture')
    try {
        New-Item -ItemType Junction -Path "$ownedFixture/junction-repo/junction" -Target "$ownedFixture/outside" | Out-Null
        New-Item -ItemType Junction -Path "$ownedFixture/junction-repo/internal-junction" -Target "$ownedFixture/junction-repo/.git" | Out-Null
        $fixtureChecks.Add([ordered]@{ name = 'junction fixtures'; status = 'Passed'; reason = 'Owned internal and external junctions created without elevation.' })
    }
    catch { $fixtureChecks.Add([ordered]@{ name = 'junction fixtures'; status = 'Blocked'; reason = $_.Exception.Message }) }
    [IO.Directory]::CreateDirectory("$ownedFixture/denied-repo/denied-directory") | Out-Null
    [IO.File]::WriteAllText("$ownedFixture/denied-repo/denied", 'synthetic unreadable attributes')
    try {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        foreach ($deniedPath in @("$ownedFixture/denied-repo/denied", "$ownedFixture/denied-repo/denied-directory")) {
            $original = Get-Acl -LiteralPath $deniedPath
            $savedAcls.Add(@{ path = $deniedPath; acl = $original })
            $modified = Get-Acl -LiteralPath $deniedPath
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Deny)
            $modified.AddAccessRule($rule)
            Set-Acl -LiteralPath $deniedPath -AclObject $modified
        }
        $fixtureChecks.Add([ordered]@{ name = 'permission-denied fixtures'; status = 'Passed'; reason = 'Read denial applied only to two owned disposable objects; originals retained for cleanup.' })
    }
    catch { $fixtureChecks.Add([ordered]@{ name = 'permission-denied fixtures'; status = 'Blocked'; reason = $_.Exception.Message }) }

    $checks.Add((Invoke-Recorded 'rustc-version' 'rustc' @('-vV')))
    $checks.Add((Invoke-Recorded 'cargo-version' 'cargo' @('--version')))
    $checks.Add((Invoke-Recorded 'format' 'cargo' @('fmt', '--all', '--', '--check')))
    $checks.Add((Invoke-Recorded 'check' 'cargo' @('check', '--offline', '--workspace')))
    $checks.Add((Invoke-Recorded 'clippy' 'cargo' @('clippy', '--offline', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings')))
    $checks.Add((Invoke-Recorded 'workspace-tests' 'cargo' @('test', '--offline', '--workspace')))
    if (@($fixtureChecks | Where-Object { $_.status -ne 'Passed' }).Count -eq 0) {
        $checks.Add((Invoke-Recorded 'windows-fixture-tests' 'cargo' @('test', '--offline', '--package', 'sentra-core', '--test', 'workspace_tests', 'workspace_windows_', '--', '--ignored', '--nocapture')))
    }
    $build = Invoke-Recorded 'benchmark-artifact' 'cargo' @('test', '--offline', '--package', 'sentra-core', '--test', 'workspace_tests', '--no-run', '--message-format=json')
    $checks.Add($build)
    if ($build.status -eq 'Passed') {
        $artifact = @($build.stdout -split "`n" | Where-Object { $_.StartsWith('{') } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'workspace_tests' -and $null -ne $_.executable })
        if ($artifact.Count -ne 1) { throw 'Expected one reviewed benchmark test executable' }
        foreach ($repeat in 1..3) {
            $measurement = Invoke-Recorded "benchmark-$repeat" $artifact[0].executable @('--ignored', '--exact', 'workspace_scale_10000_file_measurement', '--nocapture', '--test-threads=1')
            if ($measurement.status -eq 'Passed' -and ($null -eq $measurement.peak_working_set_bytes -or $measurement.peak_working_set_bytes -gt 512MB -or $measurement.stdout -notmatch 'DISCOVERY_METRICS entries=10000 elapsed_ms=(\d+) bytes=310000 complete=true')) { $measurement.status = 'Failed' }
            $checks.Add($measurement)
        }
    }
}
catch { $checks.Add([ordered]@{ name = 'validation-driver'; status = 'Blocked'; exit_code = $null; peak_working_set_bytes = $null; stdout = ''; stderr = $_.Exception.Message }) }
finally {
    foreach ($saved in $savedAcls) { Set-Acl -LiteralPath $saved.path -AclObject $saved.acl }
    if ([IO.Directory]::Exists($ownedFixture)) { Remove-OwnedFixture $ownedFixture }
    $cleanupStatus = $(if (-not [IO.Directory]::Exists($ownedFixture)) { 'Passed' } else { 'Failed' })
}

$finalInputs = Get-InputHashes
$inputsUnchanged = ($inputs | ConvertTo-Json -Compress) -ceq ($finalInputs | ConvertTo-Json -Compress)
if (-not $inputsUnchanged) { $checks.Add([ordered]@{ name = 'source-stability'; status = 'Failed'; exit_code = $null; peak_working_set_bytes = $null; stdout = ''; stderr = 'Inputs changed during validation.' }) }
$cases = [ordered]@{}
foreach ($check in $checks) {
    $individual = @([regex]::Matches($check.stdout, '(?m)^test (?<name>\S+) \.\.\. (?<outcome>ok|FAILED|ignored)') | ForEach-Object {
        $caseStatus = switch ($_.Groups['outcome'].Value) { 'ok' { 'Passed' } 'FAILED' { 'Failed' } 'ignored' { 'Not Tested' } }
        $caseName = $_.Groups['name'].Value
        if (-not $cases.Contains($caseName) -or $caseStatus -ne 'Not Tested') { $cases[$caseName] = $caseStatus }
        [ordered]@{ name = $caseName; status = $caseStatus }
    })
    $check['tests'] = $individual
    # libtest's uncaptured metric line shares stdout with its progress prefix.
    # The exact benchmark invocation and final one-test summary identify this case.
    if ($check.name -match '^benchmark-\d+$' -and $check.status -eq 'Passed' -and $check.stdout -match 'test result: ok\. 1 passed; 0 failed; 0 ignored') {
        $caseName = 'workspace_scale_10000_file_measurement'
        $cases[$caseName] = 'Passed'
        $check['tests'] = @([ordered]@{ name = $caseName; status = 'Passed' })
    }
}
$computer = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$report = [ordered]@{
    increment = 'Phase 1 / Increment 5.3'; observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    environment = [ordered]@{ powershell = $PSVersionTable.PSVersion.ToString(); os = [Runtime.InteropServices.RuntimeInformation]::OSDescription; architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString(); cpu = $cpu.Name; memory_bytes = $computer.TotalPhysicalMemory }
    input_sha256 = $inputs; inputs_unchanged_during_validation = $inputsUnchanged; fixtures = $fixtureChecks.ToArray(); checks = $checks.ToArray(); fixture_cleanup = $cleanupStatus
    test_summary = [ordered]@{ Passed = @($cases.Values | Where-Object { $_ -eq 'Passed' }).Count; Failed = @($cases.Values | Where-Object { $_ -eq 'Failed' }).Count; 'Not Tested' = @($cases.Values | Where-Object { $_ -eq 'Not Tested' }).Count }
    unique_tests = $cases
    not_tested = @('Real opaque reparse tags beyond symbolic links and junctions', 'Atomic handle-relative containment, stable file IDs and adversarial timestamp-preserving races', 'Mapped network drives, case-sensitive NTFS directories and arbitrary filesystem providers', 'Linux, macOS and ARM64')
}
[IO.File]::WriteAllText($resultPath, ($report | ConvertTo-Json -Depth 15) + "`n", [Text.UTF8Encoding]::new($false))
$checks | ForEach-Object { [PSCustomObject]@{ Name = $_.name; Status = $_.status; Exit = $_.exit_code; PeakBytes = $_.peak_working_set_bytes } } | Format-Table -AutoSize
Write-Output "Evidence: $resultPath"
if (@($checks | Where-Object { $_.status -ne 'Passed' }).Count -gt 0 -or @($fixtureChecks | Where-Object { $_.status -ne 'Passed' }).Count -gt 0 -or $cleanupStatus -ne 'Passed') { exit 1 }
