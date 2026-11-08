# F-11-03 Part 2: Process Termination Injection Experiment across 7 Boundaries
# Location: experiments/phase1/filesystem-publication/test_process_termination.ps1

$workerScript = Join-Path $PSScriptRoot "termination_worker.ps1"
if (-not (Test-Path $workerScript)) {
    throw "Worker script not found: $workerScript"
}

$tempBase = Join-Path $env:TEMP ("Sentra_ProcTerm_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempBase | Out-Null

$results = [ordered]@{}

try {
    for ($boundary = 1; $boundary -le 7; $boundary++) {
        $boundaryDir = Join-Path $tempBase ("boundary_" + $boundary)
        $stagingDir = Join-Path $boundaryDir "staging"
        $blobDir = Join-Path $boundaryDir "blobs"
        New-Item -ItemType Directory -Path $stagingDir | Out-Null
        New-Item -ItemType Directory -Path $blobDir | Out-Null

        $srcPath = Join-Path $stagingDir "content.tmp"
        $dstPath = Join-Path $blobDir "terminated_test.blob"

        # Spawn independent worker process to be terminated
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "pwsh"
        $psi.Arguments = "-NoProfile -File `"$workerScript`" -StopBoundary $boundary -StagingDir `"$stagingDir`" -BlobDir `"$blobDir`""
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.WaitForExit()
        $exitCode = $proc.ExitCode
        $proc.Dispose()

        # Inspect state at termination boundary
        $stageExists = Test-Path $srcPath
        $stageSize = if ($stageExists) { (Get-Item $srcPath).Length } else { 0 }
        $dstExists = Test-Path $dstPath
        $dstSize = if ($dstExists) { (Get-Item $dstPath).Length } else { 0 }
        $dstContent = if ($dstExists) { [IO.File]::ReadAllText($dstPath) } else { "" }

        # Recovery protocol:
        # If destination exists: verify whether it is intact.
        # If destination does NOT exist: stage file is incomplete/uncommitted, clean stage.
        # If destination exists AND stage exists: publication succeeded, finish lingering staging cleanup!
        $recoveryAction = ""
        $cleanAccidentalTarget = $false

        if ($dstExists) {
            if ($stageExists) {
                # Boundary 5 & 6: Published, but stage cleanup was interrupted. Clean stage!
                Remove-Item -Path $srcPath -Force -ErrorAction SilentlyContinue
                $recoveryAction = "CleanLingeringStage_PreserveBlob"
            } else {
                # Boundary 7: Publication and stage cleanup both finished.
                $recoveryAction = "AlreadyClean_PreserveBlob"
            }
        } else {
            # Boundaries 1-4: Destination never created. Clean incomplete stage.
            if ($stageExists) {
                Remove-Item -Path $srcPath -Force -ErrorAction SilentlyContinue
                $recoveryAction = "CleanIncompleteStage_NoBlob"
            } else {
                $recoveryAction = "AlreadyClean_NoBlob"
            }
        }

        # Verify post-recovery state
        $postStageExists = Test-Path $srcPath
        $postDstExists = Test-Path $dstPath

        $results["Boundary_$boundary"] = [ordered]@{
            Boundary = $boundary
            ProcessExitCode = $exitCode
            PreRecovery_StageExists = $stageExists
            PreRecovery_StageBytes = $stageSize
            PreRecovery_DstExists = $dstExists
            PreRecovery_DstBytes = $dstSize
            PreRecovery_DstContent = $dstContent
            RecoveryAction = $recoveryAction
            PostRecovery_StageExists = $postStageExists
            PostRecovery_DstExists = $postDstExists
            PostRecovery_DstIntact = if ($postDstExists) { ((Get-Item $dstPath).Length -eq 37) } else { $true }
        }
    }

    $summaryJson = $results | ConvertTo-Json -Depth 5
    Write-Output $summaryJson
} finally {
    if (Test-Path $tempBase) {
        Remove-Item -Path $tempBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}
