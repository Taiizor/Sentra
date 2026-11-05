[CmdletBinding()]
param([ValidateRange(30, 300)][int] $CommandTimeoutSeconds = 180)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath("$PSScriptRoot/../../..").Replace([char]92, [char]47)
$resultRoot = "$PSScriptRoot/results"
[IO.Directory]::CreateDirectory($resultRoot) | Out-Null
$resultPath = "$resultRoot/$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()).json"
$checks = [Collections.Generic.List[object]]::new()

function Get-Inputs {
    $hashes = [ordered]@{}
    $paths = @('Cargo.toml', 'Cargo.lock', 'crates/sentra-core/Cargo.toml', 'experiments/phase1/persistence/Validate.ps1') +
        @(Get-ChildItem -LiteralPath "$repoRoot/crates/sentra-core" -Recurse -File |
          Where-Object { $_.Extension -in @('.rs', '.sql') } | Sort-Object FullName |
          ForEach-Object { [IO.Path]::GetRelativePath($repoRoot, $_.FullName).Replace([char]92, [char]47) })
    foreach ($path in $paths) { $hashes[$path] = (Get-FileHash -LiteralPath "$repoRoot/$path" -Algorithm SHA256).Hash.ToLowerInvariant() }
    $hashes
}

function Invoke-Recorded {
    param([string] $Name, [string] $Executable, [string[]] $Arguments, [bool] $Native = $false)
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
        if ($Native) { $start.Environment['CC_ENABLE_DEBUG_OUTPUT'] = '1' }
        foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        if (-not $process.Start()) { throw 'Reviewed fixture command did not start' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($CommandTimeoutSeconds * 1000)
        if ($timedOut) { $process.Kill($true); $process.WaitForExit() }
        $output = $stdout.GetAwaiter().GetResult()
        Write-Host "$Name exit=$($process.ExitCode) timed_out=$timedOut"
        [ordered]@{
            name = $Name; executable = $start.FileName.Replace([char]92, [char]47); arguments = $Arguments
            status = $(if ($process.ExitCode -eq 0 -and -not $timedOut) { 'Passed' } else { 'Failed' })
            exit_code = $process.ExitCode; timed_out = $timedOut; elapsed_ms = $timer.ElapsedMilliseconds
            stdout = $output; stderr = $stderr.GetAwaiter().GetResult()
            summaries = @([regex]::Matches($output, 'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;') |
                ForEach-Object { [ordered]@{ passed = [int] $_.Groups[1].Value; failed = [int] $_.Groups[2].Value; ignored = [int] $_.Groups[3].Value } })
            tests = @([regex]::Matches($output, '(?m)^test (?<name>.+?) \.\.\. (?<outcome>ok|FAILED|ignored)') |
                ForEach-Object { [ordered]@{ name = $_.Groups['name'].Value; status = $(switch ($_.Groups['outcome'].Value) { 'ok' { 'Passed' } 'FAILED' { 'Failed' } 'ignored' { 'Not Tested' } }) } })
        }
    }
    catch { [ordered]@{ name = $Name; executable = $Executable; arguments = $Arguments; status = 'Blocked'; exit_code = $null; elapsed_ms = $timer.ElapsedMilliseconds; stdout = ''; stderr = $_.Exception.Message; summaries = @(); tests = @() } }
    finally { if ($process) { $process.Dispose() } }
}

$inputs = Get-Inputs
$checks.Add((Invoke-Recorded 'rustc-version' 'rustc' @('-vV')))
$checks.Add((Invoke-Recorded 'cargo-version' 'cargo' @('--version')))
$checks.Add((Invoke-Recorded 'resolved-metadata' 'cargo' @('metadata', '--offline', '--format-version=1', '--filter-platform', 'x86_64-pc-windows-msvc')))
$checks.Add((Invoke-Recorded 'feature-graph' 'cargo' @('tree', '--offline', '-e', 'features')))
$checks.Add((Invoke-Recorded 'native-msvc-build' 'cargo' @('build', '--workspace', '--offline', '--target', 'x86_64-pc-windows-msvc', '-vv') $true))
$checks.Add((Invoke-Recorded 'format' 'cargo' @('fmt', '--all', '--', '--check')))
$checks.Add((Invoke-Recorded 'check' 'cargo' @('check', '--workspace', '--offline')))
$checks.Add((Invoke-Recorded 'clippy' 'cargo' @('clippy', '--workspace', '--all-targets', '--all-features', '--offline', '--', '-D', 'warnings')))
$checks.Add((Invoke-Recorded 'workspace-tests' 'cargo' @('test', '--workspace', '--offline')))
$checks.Add((Invoke-Recorded 'persistence-integration' 'cargo' @('test', '--package', 'sentra-core', '--test', 'persistence_tests', '--offline')))
foreach ($round in 1..3) {
    $checks.Add((Invoke-Recorded "cross-process-repeat-$round" 'cargo' @('test', '--package', 'sentra-core', '--test', 'persistence_tests', '--offline', 'approval_cross_process_', '--', '--nocapture')))
}
$inventory = @()
$metadataCheck = $checks | Where-Object { $_.name -eq 'resolved-metadata' }
if ($metadataCheck.status -eq 'Passed') {
    $inventory = @(($metadataCheck.stdout | ConvertFrom-Json).packages | Sort-Object name, version |
        ForEach-Object { [ordered]@{ name = $_.name; version = $_.version; license = $_.license; source = $_.source } })
}
$unchanged = ($inputs | ConvertTo-Json -Compress) -ceq ((Get-Inputs) | ConvertTo-Json -Compress)
$report = [ordered]@{
    increment = 'Phase 1 / Increment 5.4.2'
    observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    environment = [ordered]@{ powershell = $PSVersionTable.PSVersion.ToString(); os = [Runtime.InteropServices.RuntimeInformation]::OSDescription; architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() }
    input_sha256 = $inputs; inputs_unchanged = $unchanged
    dependency_inventory = $inventory; checks = $checks.ToArray()
    not_tested = @('Physical disk exhaustion; actual write/fsync IOERR; power-loss durability; production load; Linux/macOS/ARM64.', 'Automatic multi-file quarantine movement/partial rename is deliberately absent; preserve the recovery set in place.', 'Database/blob reconciliation and cryptographic migration/evidence verification remain deferred.', 'Legacy workspace junction/ACL/scale cases are ignored by the ordinary suite; its separate runner records their results.', 'The ignored owned subprocess helper is actually executed by three parent integration tests, not a skipped security scenario.')
}
[IO.File]::WriteAllText($resultPath, ($report | ConvertTo-Json -Depth 30) + "`n", [Text.UTF8Encoding]::new($false))
$checks | ForEach-Object { [PSCustomObject]@{ Name = $_.name; Status = $_.status; Exit = $_.exit_code } } | Format-Table -AutoSize
Write-Output "Evidence: $resultPath"
if (-not $unchanged -or @($checks | Where-Object { $_.status -ne 'Passed' }).Count -gt 0) { exit 1 }
