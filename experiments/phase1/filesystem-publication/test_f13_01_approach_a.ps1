# Increment 1.4: F-13-01 Approach A - SetFileAttributesW While Handle Is Open
# Location: experiments/phase1/filesystem-publication/test_f13_01_approach_a.ps1

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class Win32ApproachA {
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

    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint CREATE_NEW = 1;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    public const uint FILE_ATTRIBUTE_READONLY = 0x00000001;
}
"@

$results = [ordered]@{}
$tempDir = Join-Path $env:TEMP ("Sentra_AppA_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    $stageFile = Join-Path $tempDir "stage_app_a.tmp"
    $casBlob = Join-Path $tempDir "cas_app_a.blob"

    # 1 & 2. Create staging file using CREATE_NEW and share_mode(0)
    $hExclusive = [Win32ApproachA]::CreateFileW(
        $stageFile,
        [Win32ApproachA]::GENERIC_READ -bor [Win32ApproachA]::GENERIC_WRITE,
        0, # share_mode(0) - exclusive
        [IntPtr]::Zero,
        [Win32ApproachA]::CREATE_NEW,
        [Win32ApproachA]::FILE_ATTRIBUTE_NORMAL,
        [IntPtr]::Zero
    )
    $openOk = (-not $hExclusive.IsInvalid)
    $openErr = if (-not $openOk) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

    # 3. Write, flush, and verify
    $payload = [System.Text.Encoding]::UTF8.GetBytes("payload-approach-a-12345")
    $written = 0
    $writeOk = [Win32ApproachA]::WriteFile($hExclusive, $payload, [uint32]$payload.Length, [ref]$written, [IntPtr]::Zero)
    $flushOk = [Win32ApproachA]::FlushFileBuffers($hExclusive)

    # 4. Create destination hard link while exclusive handle remains open
    $linkOk = [Win32ApproachA]::CreateHardLinkW($casBlob, $stageFile, [IntPtr]::Zero)
    $linkErr = if (-not $linkOk) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

    # 5. Call SetFileAttributesW(FILE_ATTRIBUTE_READONLY) on destination while exclusive handle is still open
    $setAttrDstOk = [Win32ApproachA]::SetFileAttributesW($casBlob, [Win32ApproachA]::FILE_ATTRIBUTE_READONLY)
    $setAttrDstErr = if (-not $setAttrDstOk) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

    # 6. Call SetFileAttributesW on staging path as well
    $setAttrSrcOk = [Win32ApproachA]::SetFileAttributesW($stageFile, [Win32ApproachA]::FILE_ATTRIBUTE_READONLY)
    $setAttrSrcErr = if (-not $setAttrSrcOk) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

    # 7. Attempt writes through original handle AFTER readonly attribute applied
    $tamperBytes = [System.Text.Encoding]::UTF8.GetBytes("-tamper-through-held-handle")
    $tamperWritten = 0
    $writeAfterReadOnly = [Win32ApproachA]::WriteFile($hExclusive, $tamperBytes, [uint32]$tamperBytes.Length, [ref]$tamperWritten, [IntPtr]::Zero)
    $writeAfterReadOnlyErr = if (-not $writeAfterReadOnly) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

    # 8. Close the handle
    $hExclusive.Close()

    # 9. Attempt new writable opens through both staging and destination names
    $hNewStageWrite = [Win32ApproachA]::CreateFileW(
        $stageFile,
        [Win32ApproachA]::GENERIC_WRITE,
        1, # FILE_SHARE_READ
        [IntPtr]::Zero,
        [Win32ApproachA]::OPEN_EXISTING,
        [Win32ApproachA]::FILE_ATTRIBUTE_NORMAL,
        [IntPtr]::Zero
    )
    $stageWriteBlocked = $hNewStageWrite.IsInvalid
    $stageWriteErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if (-not $hNewStageWrite.IsInvalid) { $hNewStageWrite.Close() }

    $hNewDstWrite = [Win32ApproachA]::CreateFileW(
        $casBlob,
        [Win32ApproachA]::GENERIC_WRITE,
        1, # FILE_SHARE_READ
        [IntPtr]::Zero,
        [Win32ApproachA]::OPEN_EXISTING,
        [Win32ApproachA]::FILE_ATTRIBUTE_NORMAL,
        [IntPtr]::Zero
    )
    $dstWriteBlocked = $hNewDstWrite.IsInvalid
    $dstWriteErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if (-not $hNewDstWrite.IsInvalid) { $hNewDstWrite.Close() }

    # Check attributes of both names
    $stageAttrs = (Get-Item $stageFile).Attributes
    $dstAttrs = (Get-Item $casBlob).Attributes

    $results["ApproachA_SetFileAttributesW"] = [ordered]@{
        OpenExclusiveSuccess = $openOk
        OpenExclusiveError = $openErr
        WriteInitialSuccess = $writeOk
        FlushSuccess = $flushOk
        HardLinkWhileOpenSuccess = $linkOk
        HardLinkError = $linkErr
        SetAttrOnDstWhileOpenSuccess = $setAttrDstOk
        SetAttrOnDstError = $setAttrDstErr
        SetAttrOnSrcWhileOpenSuccess = $setAttrSrcOk
        SetAttrOnSrcError = $setAttrSrcErr
        WriteThroughOriginalHandleAfterReadOnly = $writeAfterReadOnly
        WriteThroughOriginalHandleError = $writeAfterReadOnlyErr
        NewWritableOpenOnStageBlocked = $stageWriteBlocked
        NewWritableOpenOnStageError = $stageWriteErr # Expect 5 (ERROR_ACCESS_DENIED)
        NewWritableOpenOnDstBlocked = $dstWriteBlocked
        NewWritableOpenOnDstError = $dstWriteErr # Expect 5 (ERROR_ACCESS_DENIED)
        StageAttributes = $stageAttrs.ToString()
        DestinationAttributes = $dstAttrs.ToString()
        BothLinksShareReadOnly = (($stageAttrs -band [IO.FileAttributes]::ReadOnly) -ne 0 -and ($dstAttrs -band [IO.FileAttributes]::ReadOnly) -ne 0)
    }

    $results | ConvertTo-Json -Depth 5
} finally {
    if (Test-Path $tempDir) {
        Get-ChildItem -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $_.Attributes = [IO.FileAttributes]::Normal
        }
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
