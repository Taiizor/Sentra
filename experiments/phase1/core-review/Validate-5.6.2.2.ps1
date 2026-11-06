[CmdletBinding()]
param([ValidateRange(30, 300)][int] $CommandTimeoutSeconds = 180)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath("$PSScriptRoot/../../..").Replace([char]92, [char]47)
$resultRoot = "$PSScriptRoot/results"
[IO.Directory]::CreateDirectory($resultRoot) | Out-Null
$resultPath = "$resultRoot/5622-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()).json"
$checks = [Collections.Generic.List[object]]::new()
function Get-Inputs {
    $hashes = [ordered]@{}
    $paths = @('Cargo.toml', 'Cargo.lock', 'crates/sentra-core/Cargo.toml', 'experiments/phase1/core-review/Validate-5.6.2.2.ps1') +
        @(Get-ChildItem -LiteralPath "$repoRoot/crates/sentra-core" -Recurse -File | Where-Object { $_.Extension -in @('.rs','.sql') } | Sort-Object FullName | ForEach-Object { [IO.Path]::GetRelativePath($repoRoot,$_.FullName).Replace([char]92,[char]47) })
    foreach ($path in $paths) { $hashes[$path] = (Get-FileHash -LiteralPath "$repoRoot/$path" -Algorithm SHA256).Hash.ToLowerInvariant() }
    $hashes
}
function Invoke-Recorded {
    param([string] $Name, [string[]] $Arguments)
    $process = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = (Get-Command cargo -CommandType Application).Source
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
        if (-not $process.Start()) { throw 'Reviewed command did not start' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($CommandTimeoutSeconds * 1000)
        if ($timedOut) { $process.Kill($true); $process.WaitForExit() }
        $output = $stdout.GetAwaiter().GetResult()
        Write-Host "$Name exit=$($process.ExitCode) timed_out=$timedOut"
        [ordered]@{ name = $Name; executable = $start.FileName.Replace([char]92,[char]47); arguments = $Arguments
            status = $(if ($process.ExitCode -eq 0 -and -not $timedOut) { 'Passed' } else { 'Failed' })
            exit_code = $process.ExitCode; timed_out = $timedOut; elapsed_ms = $timer.ElapsedMilliseconds
            stdout = $output; stderr = $stderr.GetAwaiter().GetResult()
            summaries = @([regex]::Matches($output, 'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;') | ForEach-Object { [ordered]@{ passed = [int]$_.Groups[1].Value; failed = [int]$_.Groups[2].Value; ignored = [int]$_.Groups[3].Value; filtered = [int]$_.Groups[5].Value } })
            tests = @([regex]::Matches($output, '(?m)^test (?<name>.+?) \.\.\. (?<outcome>ok|FAILED|ignored)') | ForEach-Object { [ordered]@{ name = $_.Groups['name'].Value; status = $(switch ($_.Groups['outcome'].Value) { 'ok' { 'Passed' } 'FAILED' { 'Failed' } 'ignored' { 'Ignored' } }) } }) }
    }
    catch { [ordered]@{ name = $Name; arguments = $Arguments; status = 'Blocked'; exit_code = $null; stdout = ''; stderr = $_.Exception.Message; summaries = @(); tests = @() } }
    finally { if ($process) { $process.Dispose() } }
}
$inputs = Get-Inputs
$checks.Add((Invoke-Recorded 'format' @('fmt','--all','--','--check')))
$checks.Add((Invoke-Recorded 'check' @('check','--workspace','--all-targets','--all-features','--offline')))
$checks.Add((Invoke-Recorded 'clippy' @('clippy','--workspace','--all-targets','--all-features','--offline','--','-D','warnings')))
$checks.Add((Invoke-Recorded 'workspace-tests' @('test','--workspace','--offline')))
$checks.Add((Invoke-Recorded 'discovered-test-list' @('test','--workspace','--offline','--','--list')))
# Repetitions are executions of existing cases, not additional unique tests.
foreach ($case in @('workspace_directory_change_invalidates_retained_observation','workspace_directory_child_change_is_detected_with_identical_timestamp')) {
    for ($round=1; $round -le 20; $round++) {
        $checks.Add((Invoke-Recorded "$case/$round" @('test','--package','sentra-core','--test','workspace_tests','--offline',$case,'--','--exact','--nocapture')))
    }
}
$stable = ($inputs | ConvertTo-Json -Compress) -ceq ((Get-Inputs) | ConvertTo-Json -Compress)
$report = [ordered]@{
    increment = '5.6.2.2 targeted security remediation'; observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    inputs_unchanged = $stable; input_sha256 = $inputs
    environment = [ordered]@{ powershell = $PSVersionTable.PSVersion.ToString(); os = [Runtime.InteropServices.RuntimeInformation]::OSDescription; architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() }
    checks = $checks.ToArray()
    note = 'Reviewed adversarial cases now run in the ordinary suite; only two subprocess helpers and three separately-run platform cases remain ignored. Repeated/overlapping executions are not new unique tests.'
}
[IO.File]::WriteAllText($resultPath, ($report | ConvertTo-Json -Depth 25) + "`n", [Text.UTF8Encoding]::new($false))
Write-Output "Evidence: $resultPath"
if (-not $stable -or @($checks | Where-Object { $_.status -ne 'Passed' }).Count -gt 0) { exit 1 }
