# This trusted, dependency-free probe does not execute any analyzed project.
[CmdletBinding()]
param(
    [ValidateRange(1, 60)]
    [int] $CommandTimeoutSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$probeRoot = $PSScriptRoot.Replace([char]92, [char]47)
$manifestPath = "$probeRoot/Cargo.toml"
$artifactRoot = "$probeRoot/artifacts"
[IO.Directory]::CreateDirectory($artifactRoot) | Out-Null
$fixtureDirectory = "$artifactRoot/Unicode input $([char]0xFC)"
[IO.Directory]::CreateDirectory($fixtureDirectory) | Out-Null
$fixturePath = "$fixtureDirectory/fixture.txt"
[IO.File]::WriteAllText($fixturePath, "Sentra`r`nUnicode: $([char]0xFC)`r`n", [Text.UTF8Encoding]::new($false))

function Invoke-ProbeCommand {
    param(
        [string] $Name,
        [string] $Executable,
        [string[]] $Arguments,
        [int] $ExpectedExitCode = 0,
        [AllowNull()]
        [string] $ExpectedStdout = $null
    )

    $resolvedExecutable = (Get-Command $Executable -CommandType Application -ErrorAction Stop).Source
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $resolvedExecutable
    $startInfo.WorkingDirectory = $probeRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Environment['CARGO_NET_OFFLINE'] = 'true'
    $startInfo.Environment['CARGO_TERM_COLOR'] = 'never'
    foreach ($argument in $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        if (-not $process.Start()) { throw "Could not start $Executable" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($CommandTimeoutSeconds * 1000)
        if ($timedOut) {
            $process.Kill($true)
            $process.WaitForExit()
        }
        $timer.Stop()
        $stdoutText = $stdout.GetAwaiter().GetResult()
        [ordered]@{
            name = $Name
            executable = $resolvedExecutable.Replace([char]92, [char]47)
            arguments = $Arguments
            exit_code = $process.ExitCode
            expected_exit_code = $ExpectedExitCode
            expected_stdout = $ExpectedStdout
            stdout_matches = ([string]::IsNullOrEmpty($ExpectedStdout) -or $stdoutText.TrimEnd() -ceq $ExpectedStdout)
            timed_out = $timedOut
            elapsed_ms = $timer.ElapsedMilliseconds
            stdout = $stdoutText
            stderr = $stderr.GetAwaiter().GetResult()
        }
    }
    finally {
        $process.Dispose()
    }
}

$results = [Collections.Generic.List[object]]::new()
$results.Add((Invoke-ProbeCommand 'rustc-version' 'rustc' @('-vV')))
$results.Add((Invoke-ProbeCommand 'cargo-version' 'cargo' @('-vV')))
$results.Add((Invoke-ProbeCommand 'installed-targets' 'rustup' @('target', 'list', '--installed')))
$results.Add((Invoke-ProbeCommand 'rustfmt-version' 'rustfmt' @('--version')))
$results.Add((Invoke-ProbeCommand 'clippy-version' 'cargo' @('clippy', '--version')))
$results.Add((Invoke-ProbeCommand 'format' 'cargo' @('fmt', '--manifest-path', $manifestPath, '--', '--check')))
$results.Add((Invoke-ProbeCommand 'x64-check' 'cargo' @('check', '--offline', '--manifest-path', $manifestPath, '--all-targets', '--target', 'x86_64-pc-windows-msvc')))
$results.Add((Invoke-ProbeCommand 'x64-clippy' 'cargo' @('clippy', '--offline', '--manifest-path', $manifestPath, '--all-targets', '--target', 'x86_64-pc-windows-msvc', '--', '-D', 'warnings')))
$results.Add((Invoke-ProbeCommand 'x64-build' 'cargo' @('build', '--offline', '--manifest-path', $manifestPath, '--target', 'x86_64-pc-windows-msvc')))
$results.Add((Invoke-ProbeCommand 'x64-test' 'cargo' @('test', '--offline', '--manifest-path', $manifestPath, '--target', 'x86_64-pc-windows-msvc')))
$results.Add((Invoke-ProbeCommand 'x64-run-unicode-crlf' 'cargo' @('run', '--offline', '--manifest-path', $manifestPath, '--target', 'x86_64-pc-windows-msvc', '--', $fixturePath) 0 'lines=2'))
$results.Add((Invoke-ProbeCommand 'x64-run-missing-argument' 'cargo' @('run', '--offline', '--manifest-path', $manifestPath, '--target', 'x86_64-pc-windows-msvc', '--') 2))
$results.Add((Invoke-ProbeCommand 'x64-run-missing-file' 'cargo' @('run', '--offline', '--manifest-path', $manifestPath, '--target', 'x86_64-pc-windows-msvc', '--', "$artifactRoot/missing.txt") 1))
$results.Add((Invoke-ProbeCommand 'x64-link-args' 'cargo' @('rustc', '--offline', '--manifest-path', $manifestPath, '--target', 'x86_64-pc-windows-msvc', '--', '--print', 'link-args')))
$results.Add((Invoke-ProbeCommand 'arm64-check' 'cargo' @('check', '--offline', '--manifest-path', $manifestPath, '--target', 'aarch64-pc-windows-msvc')))

$vswherePath = 'C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe'
if (Test-Path -LiteralPath $vswherePath) {
    $results.Add((Invoke-ProbeCommand 'msvc-prerelease-discovery' $vswherePath @('-all', '-prerelease', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-format', 'json')))
}
$sdkRoot = $null
$sdkVersions = @()
$sdkRegistry = Get-ItemProperty -LiteralPath 'HKLM:/SOFTWARE/Microsoft/Windows Kits/Installed Roots' -ErrorAction SilentlyContinue
if ($sdkRegistry -and $sdkRegistry.PSObject.Properties['KitsRoot10']) {
    $sdkRoot = $sdkRegistry.KitsRoot10.Replace([char]92, [char]47).TrimEnd('/')
    $sdkVersions = @(Get-ChildItem -LiteralPath "$sdkRoot/Lib" -Directory | Select-Object -ExpandProperty Name)
}

$report = [ordered]@{
    schema_version = '1'
    experiment = 'phase1-rust-msvc-probe'
    observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    powershell = $PSVersionTable.PSVersion.ToString()
    host_os = [Runtime.InteropServices.RuntimeInformation]::OSDescription
    host_architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    command_timeout_seconds = $CommandTimeoutSeconds
    third_party_dependencies = @()
    input_sha256 = [ordered]@{
        manifest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        source = (Get-FileHash -LiteralPath "$probeRoot/src/main.rs" -Algorithm SHA256).Hash.ToLowerInvariant()
        runner = (Get-FileHash -LiteralPath "$probeRoot/Validate.ps1" -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    windows_sdk_root = $sdkRoot
    installed_windows_sdk_versions = $sdkVersions
    network_policy = 'Cargo offline; no networking code in the probe; no network capture performed'
    results = $results.ToArray()
}
$resultPath = "$probeRoot/results.json"
[IO.File]::WriteAllText($resultPath, ($report | ConvertTo-Json -Depth 10) + "`n", [Text.UTF8Encoding]::new($false))
$results | ForEach-Object { [PSCustomObject]@{ Name = $_.name; Exit = $_.exit_code; Expected = $_.expected_exit_code; TimedOut = $_.timed_out } } | Format-Table -AutoSize
Write-Output "Evidence: $resultPath"
if (@($results | Where-Object { $_.exit_code -ne $_.expected_exit_code -or $_.timed_out -or -not $_.stdout_matches }).Count -gt 0) { exit 1 }
