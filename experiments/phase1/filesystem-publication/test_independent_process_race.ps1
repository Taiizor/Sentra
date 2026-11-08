# F-11-03: Independent Process Race Experiment (20 rounds x 10 processes)
# Location: experiments/phase1/filesystem-publication/test_independent_process_race.ps1

$workerExe = Join-Path $PSScriptRoot "race_worker.exe"
$workerRs = Join-Path $PSScriptRoot "race_worker.rs"

if (-not (Test-Path $workerExe)) {
    if (Test-Path $workerRs) {
        Write-Host "Compiling race_worker.rs..."
        & rustc "$workerRs" -o "$workerExe"
    } else {
        throw "Worker source not found: $workerRs"
    }
}

$totalRounds = 20
$processesPerRound = 10
$roundResults = @()

$tempBase = Join-Path $env:TEMP ("Sentra_ProcRace_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempBase | Out-Null

try {
    for ($r = 1; $r -le $totalRounds; $r++) {
        $roundDir = Join-Path $tempBase ("round_" + $r)
        New-Item -ItemType Directory -Path $roundDir | Out-Null
        $dstPath = Join-Path $roundDir "published_blob.blob"

        # Create 10 source files with unique content
        $sourcePaths = @()
        for ($p = 0; $p -lt $processesPerRound; $p++) {
            $src = Join-Path $roundDir ("src_" + $p + ".tmp")
            [IO.File]::WriteAllText($src, "payload-from-worker-$p-round-$r")
            $sourcePaths += $src
        }

        # Spawn 10 independent OS processes simultaneously
        $runningProcesses = @()
        for ($p = 0; $p -lt $processesPerRound; $p++) {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $workerExe
            $psi.Arguments = "`"$($sourcePaths[$p])`" `"$dstPath`""
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true

            $proc = [System.Diagnostics.Process]::Start($psi)
            $runningProcesses += [ordered]@{
                Process = $proc
                WorkerId = $p
                ExpectedContent = "payload-from-worker-$p-round-$r"
            }
        }

        # Wait for all processes to exit
        foreach ($rp in $runningProcesses) {
            $rp.Process.WaitForExit()
        }

        # Gather exit codes
        $winners = @()
        $losers183 = @()
        $unexpectedErrors = @()

        foreach ($rp in $runningProcesses) {
            $code = $rp.Process.ExitCode
            if ($code -eq 0) {
                $winners += $rp
            } elseif ($code -eq 183) {
                $losers183 += $rp
            } else {
                $unexpectedErrors += [ordered]@{ WorkerId = $rp.WorkerId; ExitCode = $code }
            }
            $rp.Process.Dispose()
        }

        # Verify destination file
        $dstExists = Test-Path $dstPath
        $dstContent = if ($dstExists) { [IO.File]::ReadAllText($dstPath) } else { "" }
        $winnerMatchesContent = if ($winners.Count -eq 1) { ($dstContent -eq $winners[0].ExpectedContent) } else { $false }

        $roundPass = ($winners.Count -eq 1) -and ($losers183.Count -eq ($processesPerRound - 1)) -and ($unexpectedErrors.Count -eq 0) -and $winnerMatchesContent

        $roundResults += [ordered]@{
            Round = $r
            Passed = $roundPass
            WinnerCount = $winners.Count
            Losers183Count = $losers183.Count
            UnexpectedErrorsCount = $unexpectedErrors.Count
            WinnerWorkerId = if ($winners.Count -ge 1) { $winners[0].WorkerId } else { -1 }
            WinnerMatchesContent = $winnerMatchesContent
        }
    }

    $allPassed = (@($roundResults | Where-Object { $_.Passed -eq $true }).Count -eq $totalRounds)
    $summary = [ordered]@{
        TotalRounds = $totalRounds
        ProcessesPerRound = $processesPerRound
        TotalProcessExecutions = ($totalRounds * $processesPerRound)
        AllRoundsPassed = $allPassed
        RoundsSummary = $roundResults
    }

    $summaryJson = $summary | ConvertTo-Json -Depth 5
    Write-Output $summaryJson
} finally {
    if (Test-Path $tempBase) {
        Remove-Item -Path $tempBase -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $workerExe, ([System.IO.Path]::ChangeExtension($workerExe, ".pdb")) -Force -ErrorAction SilentlyContinue
}
