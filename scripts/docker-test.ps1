# Sentra Linux Docker Test Runner
# Location: scripts/docker-test.ps1
# Usage:
#   .\scripts\docker-test.ps1 -Mode all
#   .\scripts\docker-test.ps1 -Mode test -Package sentra-core -TestName persistence_tests
#   .\scripts\docker-test.ps1 -Mode check
#   .\scripts\docker-test.ps1 -Mode clippy
#   .\scripts\docker-test.ps1 -Mode fmt
#   .\scripts\docker-test.ps1 -Clean

param(
    [ValidateSet("all", "check", "test", "fmt", "clippy", "clean")]
    [string]$Mode = "all",

    [string]$Package = "",
    [string]$TestName = "",
    [switch]$Offline,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

if ($Clean) {
    Write-Host "Cleaning Sentra Docker volumes..." -ForegroundColor Cyan
    docker volume rm -f sentra_cargo_target sentra_cargo_cache 2>$null
    Write-Host "Docker test volumes cleaned." -ForegroundColor Green
    if ($Mode -eq "clean") { return }
}

# Verify Docker availability
try {
    $dockerVer = docker version --format '{{.Server.Version}}' 2>$null
    if (-not $dockerVer) {
        throw "Docker Engine is not running or not accessible."
    }
} catch {
    Write-Error "Docker is required but not running. Please start Docker Desktop."
    exit 1
}

# Image tag
$imageTag = "sentra-test-runner:1.99.0"

# Check if image exists; if not, build it from Dockerfile.test
$hasImage = docker images -q $imageTag 2>$null
if (-not $hasImage) {
    Write-Host "Building Docker test runner image: $imageTag..." -ForegroundColor Cyan
    $dockerfile = Join-Path $PSScriptRoot "..\Dockerfile.test"
    docker build -t $imageTag -f $dockerfile (Split-Path $PSScriptRoot)
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to build Docker test runner image."
        exit $LASTEXITCODE
    }
}

# Prepare host reports directory
$repoRoot = (Split-Path $PSScriptRoot -Parent)
$reportsDir = Join-Path $repoRoot "target/reports"
if (-not (Test-Path $reportsDir)) {
    New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
}

# Create named volumes if they do not exist
docker volume create sentra_cargo_target | Out-Null
docker volume create sentra_cargo_cache | Out-Null

$offlineFlag = if ($Offline) { "--offline" } else { "" }

function Invoke-ContainerCommand([string]$commandStr, [string]$logName) {
    Write-Host "`n>>> Executing: $commandStr" -ForegroundColor Yellow
    $logPath = Join-Path $reportsDir "$logName.log"
    
    $dockerArgs = @(
        "run", "--rm",
        "-v", "${repoRoot}:/workspace:ro",
        "-v", "sentra_cargo_target:/workspace/target",
        "-v", "sentra_cargo_cache:/cargo-cache",
        "-v", "${reportsDir}:/reports:rw",
        "-w", "/workspace",
        "-e", "CARGO_HOME=/cargo-cache",
        "-e", "CARGO_TARGET_DIR=/workspace/target",
        $imageTag,
        "bash", "-c", "set -o pipefail; $commandStr 2>&1 | tee /reports/$logName.log"
    )

    & docker @dockerArgs
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        Write-Host ">>> Success: $logName (Log: $logPath)" -ForegroundColor Green
    } else {
        Write-Host ">>> Failed with exit code ${exitCode}: $logName (Log: $logPath)" -ForegroundColor Red
    }
    return $exitCode
}

$overallExit = 0

if ($Mode -in @("fmt", "all")) {
    $code = Invoke-ContainerCommand "cargo fmt --all -- --check" "cargo-fmt"
    if ($code -ne 0) { $overallExit = $code }
}

if ($Mode -in @("check", "all")) {
    $cmd = "cargo check --workspace $offlineFlag"
    $code = Invoke-ContainerCommand $cmd "cargo-check"
    if ($code -ne 0) { $overallExit = $code }
}

if ($Mode -in @("clippy", "all")) {
    $cmd = "cargo clippy --workspace --all-targets --all-features $offlineFlag -- -D warnings"
    $code = Invoke-ContainerCommand $cmd "cargo-clippy"
    if ($code -ne 0) { $overallExit = $code }
}

if ($Mode -in @("test", "all")) {
    if ($Package -and $TestName) {
        $cmd = "cargo test --package $Package --test $TestName $offlineFlag"
        $code = Invoke-ContainerCommand $cmd "test-$Package-$TestName"
        if ($code -ne 0) { $overallExit = $code }
    } elseif ($Package) {
        $cmd = "cargo test --package $Package $offlineFlag"
        $code = Invoke-ContainerCommand $cmd "test-$Package"
        if ($code -ne 0) { $overallExit = $code }
    } else {
        # Run platform-independent suites in sentra-core
        $suites = @(
            "domain_tests",
            "policy_tests",
            "session_tests",
            "evidence_tests",
            "execution_tests",
            "security_tests",
            "authorization_tests",
            "persistence_tests",
            "durable_dispatch_tests",
            "manifest_tests",
            "storage_tests",
            "result_admission_tests",
            "advisory_tests",
            "diff_tests",
            "provider_tests",
            "verification_tests",
            "research_tests",
            "fuzzing_tests",
            "plugin_tests",
            "mcp_tests",
            "hosted_tests",
            "dashboard_tests",
            "fleet_tests",
            "export_tests"
        )
        $testArgs = ($suites | ForEach-Object { "--test $_" }) -join " "
        $cmd = "cargo test --package sentra-core $testArgs $offlineFlag"
        $code = Invoke-ContainerCommand $cmd "cargo-test-core-independent"
        if ($code -ne 0) { $overallExit = $code }
    }
}

exit $overallExit
