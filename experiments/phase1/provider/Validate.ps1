[CmdletBinding()]
param(
    [ValidateRange(1, 60)]
    [int] $CommandTimeoutSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$probeRoot = $PSScriptRoot.Replace([char]92, [char]47)
$manifestPath = "$probeRoot/Cargo.toml"
$resultRoot = "$probeRoot/results"
[IO.Directory]::CreateDirectory($resultRoot) | Out-Null
$runId = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString() + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$resultPath = "$resultRoot/$runId.json"

function Invoke-Check {
    param([string] $Name, [string] $Executable, [string[]] $Arguments)
    $process = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $resolved = (Get-Command $Executable -CommandType Application -ErrorAction Stop).Source
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $resolved
        $start.WorkingDirectory = $probeRoot
        $start.CreateNoWindow = $true
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.Environment['CARGO_NET_OFFLINE'] = 'true'
        $start.Environment['CARGO_TERM_COLOR'] = 'never'
        foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        if (-not $process.Start()) { throw "Could not start $Executable" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($CommandTimeoutSeconds * 1000)
        if ($timedOut) { $process.Kill($true); $process.WaitForExit() }
        $timer.Stop()
        [ordered]@{
            name = $Name
            executable = $resolved.Replace([char]92, [char]47)
            arguments = $Arguments
            status = $(if ($process.ExitCode -eq 0 -and -not $timedOut) { 'Passed' } else { 'Failed' })
            exit_code = $process.ExitCode
            timed_out = $timedOut
            elapsed_ms = $timer.ElapsedMilliseconds
            stdout = $stdout.GetAwaiter().GetResult()
            stderr = $stderr.GetAwaiter().GetResult()
        }
    }
    catch {
        [ordered]@{ name = $Name; executable = $Executable; arguments = $Arguments; status = 'Blocked'; exit_code = $null; timed_out = $false; elapsed_ms = $timer.ElapsedMilliseconds; stdout = ''; stderr = $_.Exception.Message }
    }
    finally { if ($process) { $process.Dispose() } }
}

$checks = [Collections.Generic.List[object]]::new()
$checks.Add((Invoke-Check 'rustc-version' 'rustc' @('-vV')))
$checks.Add((Invoke-Check 'cargo-version' 'cargo' @('--version')))
$checks.Add((Invoke-Check 'format' 'cargo' @('fmt', '--manifest-path', $manifestPath, '--', '--check')))
$checks.Add((Invoke-Check 'metadata' 'cargo' @('metadata', '--offline', '--manifest-path', $manifestPath, '--no-deps', '--format-version', '1')))
$checks.Add((Invoke-Check 'check' 'cargo' @('check', '--offline', '--manifest-path', $manifestPath, '--all-targets', '--target', 'x86_64-pc-windows-msvc')))
$checks.Add((Invoke-Check 'clippy' 'cargo' @('clippy', '--offline', '--manifest-path', $manifestPath, '--all-targets', '--target', 'x86_64-pc-windows-msvc', '--', '-D', 'warnings')))
$checks.Add((Invoke-Check 'contract-tests-first' 'cargo' @('test', '--offline', '--manifest-path', $manifestPath, '--target', 'x86_64-pc-windows-msvc', '--', '--test-threads=1')))
$checks.Add((Invoke-Check 'contract-tests-repeat' 'cargo' @('test', '--offline', '--manifest-path', $manifestPath, '--target', 'x86_64-pc-windows-msvc', '--', '--test-threads=1')))

$expectedTests = [regex]::Matches([IO.File]::ReadAllText("$probeRoot/tests/contract.rs"), '#\[test\]').Count
$runs = foreach ($check in $checks | Where-Object { $_.name -like 'contract-tests-*' }) {
    $cases = foreach ($match in [regex]::Matches($check.stdout, '(?m)^test (?<name>t\d{2}_\S+) \.\.\. (?<outcome>ok|FAILED|ignored)\s*$')) {
        [ordered]@{ name = $match.Groups['name'].Value; status = $(switch ($match.Groups['outcome'].Value) { 'ok' { 'Passed' } 'FAILED' { 'Failed' } 'ignored' { 'Not Tested' } }) }
    }
    [ordered]@{ name = $check.name; command_status = $check.status; tests = @($cases); count = @($cases).Count }
}
$signatures = @($runs | ForEach-Object { ($_.tests | ForEach-Object { $_.name + ':' + $_.status }) -join '|' })
$repeatMatch = $signatures.Count -eq 2 -and $signatures[0] -ceq $signatures[1]
$metadataCheck = $checks | Where-Object { $_.name -eq 'metadata' } | Select-Object -First 1
$dependencyCount = $null
if ($metadataCheck.status -eq 'Passed') {
    $metadata = $metadataCheck.stdout | ConvertFrom-Json
    $dependencyCount = @($metadata.packages | ForEach-Object { $_.dependencies } | Where-Object { $null -ne $_ }).Count
}
$hashes = [ordered]@{}
foreach ($inputFile in @('Cargo.toml', 'Cargo.lock', 'src/lib.rs', 'src/contract.rs', 'src/gateway.rs', 'src/mock.rs', 'tests/contract.rs', 'Validate.ps1')) {
    $hashes[$inputFile] = (Get-FileHash -LiteralPath "$probeRoot/$inputFile" -Algorithm SHA256).Hash.ToLowerInvariant()
}
$allCasesPassed = @($runs | Where-Object { $_.count -ne $expectedTests -or @($_.tests | Where-Object { $_.status -ne 'Passed' }).Count -gt 0 }).Count -eq 0
$runtimeOutput = ($checks | Where-Object { $_.name -like 'contract-tests-*' } | ForEach-Object { $_.stdout + $_.stderr }) -join "`n"
$canariesAbsent = $runtimeOutput -notmatch 'AUTH_SECRET_CANARY|SENSITIVE_CANARY'
$notTested = @(
    [ordered]@{ id = 'N01'; status = 'Not Tested'; name = 'Real provider SDK, authentication and backend interoperability'; reason = 'No real provider, API key or network access is used.' },
    [ordered]@{ id = 'N02'; status = 'Not Tested'; name = 'Production Core Engine integration without a provider'; reason = 'The provider-free experiment boundary passes; the production Core Engine is not implemented.' },
    [ordered]@{ id = 'N03'; status = 'Not Tested'; name = 'Real tokenizer, prices and invoice reconciliation'; reason = 'Token counts and micro-USD rates are synthetic mock fixtures.' },
    [ordered]@{ id = 'N04'; status = 'Not Tested'; name = 'Real transport cancellation, latency, backpressure and OS egress enforcement'; reason = 'Logical time and in-process mock operations do not validate remote termination or network containment.' },
    [ordered]@{ id = 'N05'; status = 'Not Tested'; name = 'JSON/SSE wire parsing, arbitrary JSON Schema and structured streaming'; reason = 'Only a narrow typed DecisionV1 object and bounded text streams are implemented in the experiment.' },
    [ordered]@{ id = 'N06'; status = 'Not Tested'; name = 'Concurrent/durable billing ledger, IPC and restart recovery'; reason = 'The mock gateway and ledger are sequential and in-memory; accepted process adapter/storage designs remain unimplemented.' }
)
$report = [ordered]@{
    schema_version = '1'
    milestone = 'Phase 1 / Milestone 3 / mock provider contract validation'
    observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    environment = [ordered]@{ powershell = $PSVersionTable.PSVersion.ToString(); host_os = [Runtime.InteropServices.RuntimeInformation]::OSDescription; architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() }
    command_timeout_seconds = $CommandTimeoutSeconds
    input_sha256 = $hashes
    third_party_dependency_count = $dependencyCount
    checks = $checks.ToArray()
    expected_contract_tests = $expectedTests
    runs = @($runs)
    repeated_outcomes_match = $repeatMatch
    synthetic_canaries_absent_from_test_logs = $canariesAbsent
    not_tested = $notTested
    summary = [ordered]@{ Passed = @($runs[0].tests | Where-Object { $_.status -eq 'Passed' }).Count; Failed = @($runs[0].tests | Where-Object { $_.status -eq 'Failed' }).Count; Blocked = @($checks | Where-Object { $_.status -eq 'Blocked' }).Count; 'Not Tested' = $notTested.Count }
}
[IO.File]::WriteAllText($resultPath, ($report | ConvertTo-Json -Depth 15) + "`n", [Text.UTF8Encoding]::new($false))
$checks | ForEach-Object { [PSCustomObject]@{ Name = $_.name; Status = $_.status; Exit = $_.exit_code } } | Format-Table -AutoSize
Write-Output "Contract tests per run: $expectedTests; repeated outcomes match: $repeatMatch; third-party dependencies: $dependencyCount"
Write-Output "Evidence: $resultPath"
if (@($checks | Where-Object { $_.status -ne 'Passed' }).Count -gt 0 -or -not $allCasesPassed -or -not $repeatMatch -or -not $canariesAbsent -or $dependencyCount -ne 0) { exit 1 }
