[CmdletBinding()]
param([ValidateRange(1, 300)][int] $CommandTimeoutSeconds = 180)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath("$PSScriptRoot/../../..").Replace([char]92, [char]47)
$resultRoot = "$PSScriptRoot/results"
[IO.Directory]::CreateDirectory($resultRoot) | Out-Null
$resultPath = "$resultRoot/$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()).json"
$probeSource = "$repoRoot/experiments/phase1/workspace/PolicyContextProbe.rs"
$probeExecutable = $null
$resolvedTarget = $null
$archive = $null
$dependencyRoot = $null
$archiveSha256 = $null
$probeSha256 = $null
$checks = [Collections.Generic.List[object]]::new()
# A cold offline target compiles dependencies/tests and launches the complete
# workspace. Its 60-second legacy budget expired after 215 passing runtime
# cases on Windows. Keep a bounded command budget, matching the core/persistence
# runners; this changes no assertion, SQLite busy timeout or execution quota.

function Get-InputHashes {
    $hashes = [ordered]@{}
    $paths = @('Cargo.toml', 'Cargo.lock', 'crates/sentra-core/Cargo.toml', 'experiments/phase1/workspace/PolicyContextProbe.rs', 'experiments/phase1/authorization/Validate.ps1') + @(Get-ChildItem -LiteralPath "$repoRoot/crates/sentra-core" -Filter '*.rs' -Recurse -File | Sort-Object FullName | ForEach-Object { [IO.Path]::GetRelativePath($repoRoot, $_.FullName).Replace([char]92, [char]47) })
    foreach ($path in $paths) { $hashes[$path] = (Get-FileHash -LiteralPath "$repoRoot/$path" -Algorithm SHA256).Hash.ToLowerInvariant() }
    return $hashes
}
$inputs = Get-InputHashes

function Invoke-Recorded {
    param([string] $Name, [string] $Executable, [string[]] $Arguments)
    $process = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = (Get-Command $Executable -CommandType Application -ErrorAction Stop).Source
        $start.WorkingDirectory = $repoRoot
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.Environment['CARGO_NET_OFFLINE'] = 'true'
        $start.Environment['CARGO_TERM_COLOR'] = 'never'
        foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        if (-not $process.Start()) { throw 'Reviewed validation command did not start' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($CommandTimeoutSeconds * 1000)
        if ($timedOut) { $process.Kill($true); $process.WaitForExit() }
        Write-Host "$Name exit=$($process.ExitCode) timed_out=$timedOut"
        [ordered]@{ name = $Name; executable = $start.FileName.Replace([char]92, [char]47); arguments = $Arguments
            status = $(if ($process.ExitCode -eq 0 -and -not $timedOut) { 'Passed' } else { 'Failed' })
            exit_code = $process.ExitCode; timed_out = $timedOut; elapsed_ms = $timer.ElapsedMilliseconds
            stdout = $stdout.GetAwaiter().GetResult(); stderr = $stderr.GetAwaiter().GetResult() }
    }
    catch { [ordered]@{ name = $Name; executable = $Executable; arguments = $Arguments; status = 'Blocked'; exit_code = $null; timed_out = $false; elapsed_ms = $timer.ElapsedMilliseconds; stdout = ''; stderr = $_.Exception.Message } }
    finally { if ($process) { $process.Dispose() } }
}

try {
    $checks.Add((Invoke-Recorded 'rustc-version' 'rustc' @('-vV')))
    $checks.Add((Invoke-Recorded 'cargo-version' 'cargo' @('--version')))
    $checks.Add((Invoke-Recorded 'dependency-metadata' 'cargo' @('metadata', '--offline', '--no-deps', '--format-version=1')))
    $targetMetadata = $checks[$checks.Count - 1]
    if ($targetMetadata.status -ne 'Passed') { throw 'Cargo target metadata unavailable; no artifact fallback is permitted' }
    $resolvedTarget = [IO.Path]::GetFullPath(($targetMetadata.stdout | ConvertFrom-Json).target_directory).Replace([char]92, [char]47)
    # A unique executable for this invocation cannot accidentally reuse an old
    # probe from either the default directory or a previous alternative run.
    $outputRoot = [IO.Path]::Combine($resolvedTarget, 'authorization-validation', [guid]::NewGuid().ToString('N')).Replace([char]92, [char]47)
    [IO.Directory]::CreateDirectory($outputRoot) | Out-Null
    $probeExecutable = "$outputRoot/policy-context-probe.exe"
    $checks.Add((Invoke-Recorded 'format' 'cargo' @('fmt', '--all', '--', '--check')))
    $checks.Add((Invoke-Recorded 'check' 'cargo' @('check', '--offline', '--workspace', '--all-targets')))
    $checks.Add((Invoke-Recorded 'clippy' 'cargo' @('clippy', '--offline', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings')))
    $checks.Add((Invoke-Recorded 'workspace-tests' 'cargo' @('test', '--offline', '--workspace')))
    $checks.Add((Invoke-Recorded 'grant-binding-regressions' 'cargo' @('test', '--offline', '--package', 'sentra-core', '--test', 'authorization_tests')))
    $checks.Add((Invoke-Recorded 'repeat-concurrency' 'cargo' @('test', '--offline', '--package', 'sentra-core', '--test', 'authorization_tests', 'concurrency_', '--', '--nocapture')))
    $checks.Add((Invoke-Recorded 'probe-format' 'rustfmt' @('--edition=2024', '--check', $probeSource)))
    $build = Invoke-Recorded 'probe-library-artifact' 'cargo' @('build', '--offline', '--package', 'sentra-core', '--message-format=json')
    $checks.Add($build)
    if ($build.status -eq 'Passed') {
        $archives = @($build.stdout -split "`n" | Where-Object { $_.StartsWith('{') } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'sentra_core' } | ForEach-Object { $_.filenames } | Where-Object { $_.EndsWith('.rlib') })
        if ($archives.Count -ne 1) { throw 'Expected one reviewed Core library archive' }
        $archive = $archives[0].Replace([char]92, [char]47)
        $archive = [IO.Path]::GetFullPath($archive).Replace([char]92, [char]47)
        $relativeArchive = [IO.Path]::GetRelativePath($resolvedTarget, $archive)
        if ([IO.Path]::IsPathRooted($relativeArchive) -or ($relativeArchive -split '[/\\]')[0] -eq '..' -or -not [IO.File]::Exists($archive)) {
            throw 'Cargo archive is outside this invocation target directory or unavailable'
        }
        $archiveDirectory = [IO.Path]::GetDirectoryName($archive)
        $dependencyRoot = if ([IO.Path]::GetFileName($archiveDirectory) -eq 'deps') { $archiveDirectory } else { [IO.Path]::Combine($archiveDirectory, 'deps') }
        $dependencyRoot = $dependencyRoot.Replace([char]92, [char]47)
        if (-not [IO.Directory]::Exists($dependencyRoot)) { throw 'Dependency directory for the actual Cargo archive is unavailable' }
        $archiveSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        $compiled = Invoke-Recorded 'original-probe-compile' 'rustc' @('--edition=2024', '--crate-name', 'policy_context_probe', $probeSource, '--extern', "sentra_core=$archive", '-L', "dependency=$dependencyRoot", '-o', $probeExecutable)
        $checks.Add($compiled)
        if ($compiled.status -eq 'Passed') {
            if (-not [IO.File]::Exists($probeExecutable)) { throw 'This invocation produced no probe executable' }
            $probeSha256 = (Get-FileHash -LiteralPath $probeExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
            $probe = Invoke-Recorded 'original-a-to-b-probe' $probeExecutable @()
            if ($probe.status -eq 'Passed' -and $probe.stdout -notmatch 'POLICY_CONTEXT_BINDING=Passed: mismatched metadata action rejected; matching action accepted once; replay rejected') { $probe.status = 'Failed' }
            $checks.Add($probe)
        }
    }
}
catch { $checks.Add([ordered]@{ name = 'validation-driver'; status = 'Blocked'; exit_code = $null; timed_out = $false; stdout = ''; stderr = $_.Exception.Message }) }

$unchanged = ($inputs | ConvertTo-Json -Compress) -ceq ((Get-InputHashes) | ConvertTo-Json -Compress)
foreach ($check in $checks) {
    $check['tests'] = @([regex]::Matches($check.stdout, '(?m)^test (?<name>.+?) \.\.\. (?<outcome>ok|FAILED|ignored)') | ForEach-Object {
        [ordered]@{ name = $_.Groups['name'].Value; status = $(switch ($_.Groups['outcome'].Value) { 'ok' { 'Passed' } 'FAILED' { 'Failed' } 'ignored' { 'Not Tested' } }) }
    })
    $check['summaries'] = @([regex]::Matches($check.stdout, 'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;') | ForEach-Object {
        [ordered]@{ passed = [int] $_.Groups[1].Value; failed = [int] $_.Groups[2].Value; ignored = [int] $_.Groups[3].Value }
    })
}
$metadataCheck = $checks | Where-Object { $_.name -eq 'dependency-metadata' } | Select-Object -First 1
$dependencyCount = $null
$approvedDependencies = $false
if ($null -ne $metadataCheck -and $metadataCheck.status -eq 'Passed') {
    $metadata = $metadataCheck.stdout | ConvertFrom-Json
    $dependencyCount = @($metadata.packages | ForEach-Object { $_.dependencies } | Where-Object { $null -ne $_ -and $null -ne $_.source }).Count
    $dependencies = @($metadata.packages | Where-Object { $_.name -eq 'sentra-core' } | ForEach-Object { $_.dependencies })
    # Increment 6.1 adds exactly one local CLI -> Core edge, no third-party package.
    # Keep the audited external dependency restriction and validate the path edge.
    $localDependencies = @($metadata.packages | ForEach-Object { $_.dependencies } | Where-Object { $null -ne $_ -and $null -eq $_.source })
    $cliDependencies = @($metadata.packages | Where-Object { $_.name -eq 'sentra-cli' } | ForEach-Object { $_.dependencies })
    $approvedDependencies = $dependencyCount -eq 3 -and $dependencies.Count -eq 3 -and $localDependencies.Count -eq 1 -and $cliDependencies.Count -eq 1
    if ($approvedDependencies) {
        $edge = $cliDependencies[0]
        $approvedDependencies = $edge.name -eq 'sentra-core' -and $edge.req -eq '=0.1.0' -and $null -eq $edge.source -and $edge.path.Replace([char]92, [char]47) -eq "$repoRoot/crates/sentra-core"
    }
    foreach ($spec in @(@('rusqlite', '=0.32.1', 'bundled'), @('serde', '=1.0.229', 'derive'), @('serde_json', '=1.0.154', ''))) {
        $dependency = @($dependencies | Where-Object { $_.name -eq $spec[0] })
        if ($dependency.Count -ne 1 -or $dependency[0].req -ne $spec[1]) { $approvedDependencies = $false; continue }
        if ($spec[2] -and $spec[2] -notin $dependency[0].features) { $approvedDependencies = $false }
    }
}
$workspace = $checks | Where-Object { $_.name -eq 'workspace-tests' } | Select-Object -First 1
$repeat = $checks | Where-Object { $_.name -eq 'repeat-concurrency' } | Select-Object -First 1
$concurrencyVerified = $null -ne $repeat -and $repeat.status -eq 'Passed' -and $repeat.stdout -match 'CONCURRENCY rounds=64 matching_successes=64 matching_replays=64 mismatches=384' -and $repeat.stdout -match 'CONCURRENCY rounds=32 mismatches=256 legitimate_successes=32'
$workspaceSummaries = if ($null -ne $workspace) { @($workspace.summaries) } else { @() }
$report = [ordered]@{
    increment = 'Phase 1 / Increment 5.3.1'; observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    environment = [ordered]@{ powershell = $PSVersionTable.PSVersion.ToString(); os = [Runtime.InteropServices.RuntimeInformation]::OSDescription; architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() }
    artifacts = [ordered]@{ requested_target_dir = $env:CARGO_TARGET_DIR; resolved_target_dir = $resolvedTarget; archive = $archive; dependency_dir = $dependencyRoot; probe = $probeExecutable; archive_sha256 = $archiveSha256; probe_sha256 = $probeSha256 }
    command_timeout_seconds = $CommandTimeoutSeconds
    input_sha256 = $inputs; inputs_unchanged = $unchanged; third_party_dependencies = $dependencyCount; approved_dependencies = $approvedDependencies; checks = $checks.ToArray()
    workspace_summary = [ordered]@{ Passed = ($workspaceSummaries | ForEach-Object { $_.passed } | Measure-Object -Sum).Sum; Failed = ($workspaceSummaries | ForEach-Object { $_.failed } | Measure-Object -Sum).Sum; 'Not Tested' = ($workspaceSummaries | ForEach-Object { $_.ignored } | Measure-Object -Sum).Sum }
    repeated_concurrency_verified = $concurrencyVerified
    not_tested = @('Three unchanged 5.3 Windows fixture/scale cases are explicitly ignored by ordinary workspace tests; prior results remain historical.', 'Remote human authentication, persistent/cross-process receipts, external dispatch, Linux/macOS/ARM64 and filesystem containment remain outside this correction.')
}
[IO.File]::WriteAllText($resultPath, ($report | ConvertTo-Json -Depth 20) + "`n", [Text.UTF8Encoding]::new($false))
$checks | ForEach-Object { [PSCustomObject]@{ Name = $_.name; Status = $_.status; Exit = $_.exit_code } } | Format-Table -AutoSize
Write-Output "Evidence: $resultPath"
if (-not $unchanged -or -not $approvedDependencies -or -not $concurrencyVerified -or @($checks | Where-Object { $_.status -ne 'Passed' }).Count -gt 0) { exit 1 }
