[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath("$PSScriptRoot/../../..").Replace([char]92, [char]47)
$validator = "$PSScriptRoot/Validate.ps1"
$runRoot = [IO.Path]::Combine($repoRoot, 'target', "authorization-portability-$([guid]::NewGuid().ToString('N'))").Replace([char]92, [char]47)
$spaces = "$runRoot/absolute target with spaces"
$cold = "$runRoot/initially empty target"
foreach ($directory in @($runRoot, $spaces, $cold)) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
$resultPath = "$PSScriptRoot/results/portability-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()).json"
$driverHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$cases = [Collections.Generic.List[object]]::new()

foreach ($scenario in @(
    @{ name = 'default'; target = $null; cwd = $repoRoot; cold = $false },
    @{ name = 'absolute-spaces'; target = $spaces; cwd = $runRoot; cold = $false },
    @{ name = 'initially-empty'; target = $cold; cwd = $repoRoot; cold = $true },
    @{ name = 'reuse'; target = $cold; cwd = $repoRoot; cold = $false }
)) {
    $process = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $emptyBefore = $null
    $targetExistsBefore = $null
    try {
        if ($null -ne $scenario.target) {
            $targetExistsBefore = [IO.Directory]::Exists($scenario.target)
            $emptyBefore = @(Get-ChildItem -LiteralPath $scenario.target -Force).Count -eq 0
            if (-not [IO.Path]::IsPathFullyQualified($scenario.target)) { throw 'Alternative target must be absolute' }
            if ($scenario.cold -and -not $emptyBefore) { throw 'Cold target is not initially empty' }
            if ($scenario.name -eq 'reuse' -and $emptyBefore) { throw 'Warm invocation has no previous build artifacts' }
        }
        Write-Host "Portability case=$($scenario.name) starting"
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = (Get-Command pwsh -CommandType Application).Source
        $start.WorkingDirectory = $scenario.cwd
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.Environment['CARGO_NET_OFFLINE'] = 'true'
        if ($null -eq $scenario.target) { $start.Environment.Remove('CARGO_TARGET_DIR') | Out-Null }
        else { $start.Environment['CARGO_TARGET_DIR'] = $scenario.target }
        foreach ($argument in @('-NoProfile','-File',$validator)) { $start.ArgumentList.Add($argument) }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        if (-not $process.Start()) { throw 'Validator process did not start' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit(900000)
        if ($timedOut) { $process.Kill($true); $process.WaitForExit() }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $match = [regex]::Match($stdout, '(?m)^Evidence:\s*(.+?)\r?$')
        if (-not $match.Success) { throw "Validator produced no raw record (exit=$($process.ExitCode)): $stderr" }
        $rawPath = $match.Groups[1].Value.Trim()
        $raw = Get-Content -LiteralPath $rawPath -Raw | ConvertFrom-Json
        $expectedTarget = if ($null -eq $scenario.target) { $raw.artifacts.resolved_target_dir } else { $scenario.target }
        $targetMatches = [IO.Path]::GetFullPath($raw.artifacts.resolved_target_dir) -eq [IO.Path]::GetFullPath($expectedTarget)
        $archiveWithinTarget = -not [IO.Path]::IsPathRooted([IO.Path]::GetRelativePath($expectedTarget,$raw.artifacts.archive)) -and ([IO.Path]::GetRelativePath($expectedTarget,$raw.artifacts.archive) -split '[/\\]')[0] -ne '..'
        $passed = $process.ExitCode -eq 0 -and -not $timedOut -and $raw.inputs_unchanged -and $targetMatches -and $archiveWithinTarget -and @($raw.checks | Where-Object { $_.status -ne 'Passed' }).Count -eq 0
        $cases.Add([ordered]@{ name = $scenario.name; status = $(if ($passed) { 'Passed' } else { 'Failed' }); exit_code = $process.ExitCode; timed_out = $timedOut; elapsed_ms = $timer.ElapsedMilliseconds
            command = @($start.FileName,'-NoProfile','-File',$validator); working_directory = $scenario.cwd; cargo_target_dir = $scenario.target
            target_existed_before = $targetExistsBefore; target_empty_before = $emptyBefore
            evidence = [IO.Path]::GetRelativePath($repoRoot,$rawPath).Replace([char]92,[char]47)
            target_matches = $targetMatches; archive_within_target = $archiveWithinTarget; artifacts = $raw.artifacts; checks = $raw.checks.Count
            stdout = $stdout; stderr = $stderr })
        Write-Host "Portability case=$($scenario.name) status=$($cases[$cases.Count-1].status)"
    }
    catch { $cases.Add([ordered]@{ name = $scenario.name; status = 'Blocked'; elapsed_ms = $timer.ElapsedMilliseconds; error = $_.Exception.Message; cargo_target_dir = $scenario.target; target_empty_before = $emptyBefore }) }
    finally { if ($null -ne $process) { $process.Dispose() } }
}
$coldRun = @($cases | Where-Object { $_.name -eq 'initially-empty' -and $_.status -eq 'Passed' })
$warmRun = @($cases | Where-Object { $_.name -eq 'reuse' -and $_.status -eq 'Passed' })
$reuseVerified = $coldRun.Count -eq 1 -and $warmRun.Count -eq 1 -and $coldRun[0].artifacts.archive -eq $warmRun[0].artifacts.archive -and $coldRun[0].artifacts.archive_sha256 -eq $warmRun[0].artifacts.archive_sha256 -and $coldRun[0].artifacts.probe -ne $warmRun[0].artifacts.probe
$stable = $driverHash -eq (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$record = [ordered]@{ increment = '5.6.2.2.2 validator portability'; observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o'); driver_sha256 = $driverHash; driver_unchanged = $stable
    fixture_root = $runRoot; cases = $cases.ToArray(); reuse_verified = $reuseVerified
    note = 'Cached approved dependencies only; no source/host configuration changes. Build artifacts are retained for the required warm invocation. Each validator compiles a unique probe using this Cargo invocation archive/dependency path.' }
[IO.File]::WriteAllText($resultPath,($record | ConvertTo-Json -Depth 25) + "`n",[Text.UTF8Encoding]::new($false))
Write-Output "Evidence: $resultPath"
if (-not $stable -or -not $reuseVerified -or @($cases | Where-Object { $_.status -ne 'Passed' }).Count -gt 0) { exit 1 }
