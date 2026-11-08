# Cross-Volume Staging & Publication Protocol Experiment
# Location: experiments/phase1/filesystem-publication/test_cross_volume_staging.ps1

$tempC = Join-Path $env:TEMP ("Sentra_CrossC_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempC | Out-Null

$results = [ordered]@{}

# Check if drive E: is available
$driveEAvailable = Test-Path "E:\"

if (-not $driveEAvailable) {
    $results["CrossVolumeTest"] = [ordered]@{
        Skipped = $true
        Reason = "Drive E: is not accessible"
    }
} else {
    $tempE = "E:\Sentra_CrossE_" + [Guid]::NewGuid().ToString("N")
    New-Item -ItemType Directory -Path $tempE | Out-Null

    try {
        # 1. Source created on C:
        $sourceC = Join-Path $tempC "source_payload.tmp"
        $payload = [System.Text.Encoding]::UTF8.GetBytes("cross-volume-test-payload-12345")
        [System.IO.File]::WriteAllBytes($sourceC, $payload)

        # 2. Destination volume E: directories
        $stagingDirE = Join-Path $tempE "staging"
        $blobsDirE = Join-Path $tempE "blobs"
        New-Item -ItemType Directory -Path $stagingDirE | Out-Null
        New-Item -ItemType Directory -Path $blobsDirE | Out-Null

        $stageFileE = Join-Path $stagingDirE "staged_content.tmp"
        $finalBlobE = Join-Path $blobsDirE "cas_blob.blob"

        # 3. Stream copy into destination-volume staging with exclusive creation
        $fsSrc = [System.IO.File]::OpenRead($sourceC)
        $fsDst = [System.IO.File]::Create($stageFileE)
        $fsSrc.CopyTo($fsDst)
        $fsDst.Flush()
        $fsDst.Close()
        $fsSrc.Close()

        # 4. Verify byte length on E:
        $stageLenE = (Get-Item $stageFileE).Length

        # 5. Same-volume hard link within E:
        Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        public class Win32Cross {
            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool CreateHardLinkW(string lpFileName, string lpExistingFileName, IntPtr lpSecurityAttributes);
            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool SetFileAttributesW(string lpFileName, uint dwFileAttributes);
        }
"@ -ErrorAction SilentlyContinue

        $linkSuccess = [Win32Cross]::CreateHardLinkW($finalBlobE, $stageFileE, [IntPtr]::Zero)
        $linkErr = if (-not $linkSuccess) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

        # 6. Collision rejection test on E:
        $secondStageFileE = Join-Path $stagingDirE "second_stage.tmp"
        [System.IO.File]::WriteAllText($secondStageFileE, "second-stage-payload")
        $collisionLink = [Win32Cross]::CreateHardLinkW($finalBlobE, $secondStageFileE, [IntPtr]::Zero)
        $collisionErr = if (-not $collisionLink) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }
        $destinationContent = [System.IO.File]::ReadAllText($finalBlobE)

        # 7. Cleanup staging on E:
        Remove-Item -Path $stageFileE -Force
        Remove-Item -Path $secondStageFileE -Force
        [Win32Cross]::SetFileAttributesW($finalBlobE, 1) | Out-Null # ReadOnly

        $results["CrossVolumeStagingProtocol"] = [ordered]@{
            SourceOnC_Bytes = $payload.Length
            StagedOnE_Bytes = $stageLenE
            SameVolumeLinkOnE_Succeeded = $linkSuccess
            SameVolumeLinkOnE_Error = $linkErr
            CollisionRejectedOnE = (-not $collisionLink)
            CollisionErrorCode = $collisionErr # Expect 183
            DestinationPreservedOnCollision = ($destinationContent -eq "cross-volume-test-payload-12345")
            DestinationIsReadOnly = (((Get-Item $finalBlobE).Attributes -band [IO.FileAttributes]::ReadOnly) -ne 0)
            StagingCleanedOnE = (-not (Test-Path $stageFileE))
        }

    } finally {
        if (Test-Path $tempE) {
            Get-ChildItem -Path $tempE -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                $_.Attributes = [IO.FileAttributes]::Normal
            }
            Remove-Item -Path $tempE -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

if (Test-Path $tempC) {
    Remove-Item -Path $tempC -Recurse -Force -ErrorAction SilentlyContinue
}

$results | ConvertTo-Json
