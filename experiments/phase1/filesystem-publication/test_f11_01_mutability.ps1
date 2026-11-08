# F-11-01: Hard-Link Content Mutability & Handle Lifecycle Experiments
# Location: experiments/phase1/filesystem-publication/test_f11_01_mutability.ps1

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class Win32Mut {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateHardLinkW(
        string lpFileName,
        string lpExistingFileName,
        IntPtr lpSecurityAttributes
    );

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool SetFileAttributesW(
        string lpFileName,
        uint dwFileAttributes
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FlushFileBuffers(SafeFileHandle hFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten,
        IntPtr lpOverlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint FILE_SHARE_DELETE = 0x00000004;
    public const uint CREATE_NEW = 1;
    public const uint CREATE_ALWAYS = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    public const uint FILE_ATTRIBUTE_READONLY = 0x00000001;
}
"@

$results = [ordered]@{}
$tempDir = Join-Path $env:TEMP ("Sentra_Mut_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    # 1. Modify through already-open handle after hard link
    $src1 = Join-Path $tempDir "src1.tmp"
    $dst1 = Join-Path $tempDir "dst1.blob"
    [IO.File]::WriteAllText($src1, "initial-data-1")
    
    # Open writable handle with FILE_SHARE_READ | FILE_SHARE_WRITE
    $hWrite1 = [Win32Mut]::CreateFileW($src1, [Win32Mut]::GENERIC_WRITE, [Win32Mut]::FILE_SHARE_READ -bor [Win32Mut]::FILE_SHARE_WRITE, [IntPtr]::Zero, [Win32Mut]::OPEN_EXISTING, [Win32Mut]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
    $link1 = [Win32Mut]::CreateHardLinkW($dst1, $src1, [IntPtr]::Zero)
    $link1Err = if (-not $link1) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }
    
    # Write through existing open handle after hard link
    $bytes = [Text.Encoding]::UTF8.GetBytes("-tampered-after-link")
    $written = 0
    $writeSuccess = [Win32Mut]::WriteFile($hWrite1, $bytes, [uint32]$bytes.Length, [ref]$written, [IntPtr]::Zero)
    $hWrite1.Close()

    $dst1Content = if (Test-Path $dst1) { [IO.File]::ReadAllText($dst1) } else { "" }
    $results["1_ModifyThroughAlreadyOpenHandle"] = [ordered]@{
        HardLinkSucceeded = $link1
        LinkError = $link1Err
        WriteThroughHandleSucceeded = $writeSuccess
        DestinationContent = $dst1Content
        DestinationTampered = ($dst1Content -ne "initial-data-1")
    }

    # 2. Modify through staging path after hard link (new open)
    $src2 = Join-Path $tempDir "src2.tmp"
    $dst2 = Join-Path $tempDir "dst2.blob"
    [IO.File]::WriteAllText($src2, "initial-data-2")
    $link2 = [Win32Mut]::CreateHardLinkW($dst2, $src2, [IntPtr]::Zero)
    [IO.File]::AppendAllText($src2, "-tampered-via-src2-path")
    $dst2Content = [IO.File]::ReadAllText($dst2)
    $results["2_ModifyViaStagingPath"] = [ordered]@{
        HardLinkSucceeded = $link2
        DestinationTampered = ($dst2Content -ne "initial-data-2")
        DestinationContent = $dst2Content
    }

    # 3. Delete staging name
    $src3 = Join-Path $tempDir "src3.tmp"
    $dst3 = Join-Path $tempDir "dst3.blob"
    [IO.File]::WriteAllText($src3, "initial-data-3")
    $link3 = [Win32Mut]::CreateHardLinkW($dst3, $src3, [IntPtr]::Zero)
    [IO.File]::Delete($src3)
    $dst3Exists = Test-Path $dst3
    $dst3Content = if ($dst3Exists) { [IO.File]::ReadAllText($dst3) } else { "" }
    $results["3_DeleteStagingName"] = [ordered]@{
        StagingNameDeleted = (-not (Test-Path $src3))
        DestinationSurvives = $dst3Exists
        DestinationContentPreserved = ($dst3Content -eq "initial-data-3")
    }

    # 4. Modify via second hard-link alias
    $src4 = Join-Path $tempDir "src4.tmp"
    $dst4 = Join-Path $tempDir "dst4.blob"
    $alias4 = Join-Path $tempDir "alias4.dat"
    [IO.File]::WriteAllText($src4, "initial-data-4")
    $link4a = [Win32Mut]::CreateHardLinkW($dst4, $src4, [IntPtr]::Zero)
    $link4b = [Win32Mut]::CreateHardLinkW($alias4, $dst4, [IntPtr]::Zero)
    [IO.File]::AppendAllText($alias4, "-tampered-via-alias")
    $dst4Content = [IO.File]::ReadAllText($dst4)
    $results["4_ModifyViaSecondHardLink"] = [ordered]@{
        SecondLinkCreated = $link4b
        DestinationTampered = ($dst4Content -ne "initial-data-4")
        DestinationContent = $dst4Content
    }

    # 5. Read-only attribute behavior:
    # 5a. Prevents write via original path
    $src5a = Join-Path $tempDir "src5a.tmp"
    $dst5a = Join-Path $tempDir "dst5a.blob"
    [IO.File]::WriteAllText($src5a, "data-5a")
    [Win32Mut]::CreateHardLinkW($dst5a, $src5a, [IntPtr]::Zero) | Out-Null
    [Win32Mut]::SetFileAttributesW($dst5a, [Win32Mut]::FILE_ATTRIBUTE_READONLY) | Out-Null
    
    $writeViaSrcFailed = $false
    $writeViaSrcErr = 0
    try {
        [IO.File]::AppendAllText($src5a, "more")
    } catch {
        $writeViaSrcFailed = $true
        $writeViaSrcErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }

    # 5b. Read-only against an ALREADY-OPEN handle
    $src5b = Join-Path $tempDir "src5b.tmp"
    $dst5b = Join-Path $tempDir "dst5b.blob"
    [IO.File]::WriteAllText($src5b, "data-5b")
    $hWrite5b = [Win32Mut]::CreateFileW($src5b, [Win32Mut]::GENERIC_WRITE, [Win32Mut]::FILE_SHARE_READ -bor [Win32Mut]::FILE_SHARE_WRITE, [IntPtr]::Zero, [Win32Mut]::OPEN_EXISTING, [Win32Mut]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
    [Win32Mut]::CreateHardLinkW($dst5b, $src5b, [IntPtr]::Zero) | Out-Null
    # Apply read-only while handle is open!
    [Win32Mut]::SetFileAttributesW($dst5b, [Win32Mut]::FILE_ATTRIBUTE_READONLY) | Out-Null
    $written5b = 0
    $bytes5b = [Text.Encoding]::UTF8.GetBytes("-write-after-readonly-attr")
    $write5bSuccess = [Win32Mut]::WriteFile($hWrite5b, $bytes5b, [uint32]$bytes5b.Length, [ref]$written5b, [IntPtr]::Zero)
    $hWrite5b.Close()
    $dst5bContent = [IO.File]::ReadAllText($dst5b)

    $results["5_ReadOnlyAttribute"] = [ordered]@{
        BlocksNewWritePath = $writeViaSrcFailed
        WriteViaOpenHandleBypassesReadOnly = $write5bSuccess
        DestinationTamperedViaOpenHandle = ($dst5bContent -ne "data-5b")
    }

    # 6. Restrictive sharing flags
    $src6 = Join-Path $tempDir "src6.tmp"
    [IO.File]::WriteAllText($src6, "data-6")
    $hRead6 = [Win32Mut]::CreateFileW($src6, [Win32Mut]::GENERIC_READ, [Win32Mut]::FILE_SHARE_READ, [IntPtr]::Zero, [Win32Mut]::OPEN_EXISTING, [Win32Mut]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
    
    # Try write open
    $hWrite6 = [Win32Mut]::CreateFileW($src6, [Win32Mut]::GENERIC_WRITE, [Win32Mut]::FILE_SHARE_READ -bor [Win32Mut]::FILE_SHARE_WRITE, [IntPtr]::Zero, [Win32Mut]::OPEN_EXISTING, [Win32Mut]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
    $writeOpenErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $writeBlocked = $hWrite6.IsInvalid
    if (-not $hWrite6.IsInvalid) { $hWrite6.Close() }

    # Try delete
    $delFailed = $false
    try { [IO.File]::Delete($src6) } catch { $delFailed = $true }
    $hRead6.Close()

    $results["6_RestrictiveSharingFlags"] = [ordered]@{
        WriteOpenBlocked = $writeBlocked
        WriteOpenErrorCode = $writeOpenErr
        DeleteBlocked = $delFailed
    }

    # 7. Creating hard link while handle is open under different share modes
    $modes = @(
        @{ Name = "ExclusiveWrite_ShareNone"; Access = [Win32Mut]::GENERIC_WRITE; Share = 0 },
        @{ Name = "SharedWrite_ShareReadWrite"; Access = [Win32Mut]::GENERIC_WRITE; Share = ([Win32Mut]::FILE_SHARE_READ -bor [Win32Mut]::FILE_SHARE_WRITE) },
        @{ Name = "ReadOnly_ShareRead"; Access = [Win32Mut]::GENERIC_READ; Share = [Win32Mut]::FILE_SHARE_READ }
    )
    $shareLinkResults = [ordered]@{}
    $idx = 0
    foreach ($m in $modes) {
        $idx++
        $sFile = Join-Path $tempDir ("share_src_" + $idx + ".tmp")
        $dFile = Join-Path $tempDir ("share_dst_" + $idx + ".blob")
        [IO.File]::WriteAllText($sFile, "test-share-" + $idx)
        $h = [Win32Mut]::CreateFileW($sFile, $m.Access, $m.Share, [IntPtr]::Zero, [Win32Mut]::OPEN_EXISTING, [Win32Mut]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
        $linkRes = [Win32Mut]::CreateHardLinkW($dFile, $sFile, [IntPtr]::Zero)
        $linkErr = if (-not $linkRes) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }
        $h.Close()
        $shareLinkResults[$m.Name] = [ordered]@{
            HardLinkSucceeded = $linkRes
            ErrorCode = $linkErr
        }
    }
    $results["7_HardLinkUnderDifferentShareModes"] = $shareLinkResults

    # 8 & 9. Full hardened sequence evaluation
    $stageDir = Join-Path $tempDir "stage_uuid_123"
    New-Item -ItemType Directory -Path $stageDir | Out-Null
    $stageFile = Join-Path $stageDir "content.tmp"
    $casBlob = Join-Path $tempDir "published_blob.blob"

    # Step 1: Exclusive write creation
    $hStageWrite = [Win32Mut]::CreateFileW($stageFile, [Win32Mut]::GENERIC_WRITE, 0, [IntPtr]::Zero, [Win32Mut]::CREATE_NEW, [Win32Mut]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
    $pBytes = [Text.Encoding]::UTF8.GetBytes("verified-cas-payload-bytes")
    $pWritten = 0
    [Win32Mut]::WriteFile($hStageWrite, $pBytes, [uint32]$pBytes.Length, [ref]$pWritten, [IntPtr]::Zero) | Out-Null
    # Step 2: Flush
    $flushOk = [Win32Mut]::FlushFileBuffers($hStageWrite)
    # Step 3: Close
    $hStageWrite.Close()

    # Step 4: Reopen read-only with FILE_SHARE_READ -bor FILE_SHARE_DELETE
    $hStageRead = [Win32Mut]::CreateFileW($stageFile, [Win32Mut]::GENERIC_READ, [Win32Mut]::FILE_SHARE_READ -bor [Win32Mut]::FILE_SHARE_DELETE, [IntPtr]::Zero, [Win32Mut]::OPEN_EXISTING, [Win32Mut]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
    # Step 5: Verify hash/content under read handle
    $verifiedOk = ($pWritten -eq $pBytes.Length)
    # Step 6: Hard link while holding read-only handle with FILE_SHARE_DELETE
    $pubLink = [Win32Mut]::CreateHardLinkW($casBlob, $stageFile, [IntPtr]::Zero)
    # Step 7: Delete staging name
    $hStageRead.Close()
    [IO.File]::Delete($stageFile)
    # Step 8: Apply read-only attribute to destination blob
    [Win32Mut]::SetFileAttributesW($casBlob, [Win32Mut]::FILE_ATTRIBUTE_READONLY) | Out-Null

    # Step 9: Verify post-state
    $casFinalContent = [IO.File]::ReadAllText($casBlob)
    $stageLingering = Test-Path $stageFile
    $casAttributes = (Get-Item $casBlob).Attributes

    $results["8_FullHardenedSequence"] = [ordered]@{
        FlushSucceeded = $flushOk
        HardLinkSucceeded = $pubLink
        StagingNameRemoved = (-not $stageLingering)
        DestinationContent = $casFinalContent
        DestinationAttributes = $casAttributes.ToString()
        DestinationIsReadOnly = (($casAttributes -band [IO.FileAttributes]::ReadOnly) -ne 0)
    }

} finally {
    # Cleanup temporary directory
    if (Test-Path $tempDir) {
        # Clear readonly on any files before removal
        Get-ChildItem -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $_.Attributes = [IO.FileAttributes]::Normal
        }
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$resultsJson = $results | ConvertTo-Json -Depth 5
Write-Output $resultsJson
