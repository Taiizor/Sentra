# Increment 1.4: F-13-01 Approach B - SetFileInformationByHandle(FileBasicInfo)
# Location: experiments/phase1/filesystem-publication/test_f13_01_approach_b.ps1

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class Win32ApproachB {
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

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_BASIC_INFO {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint FileAttributes;
    }

    public enum FILE_INFO_BY_HANDLE_CLASS {
        FileBasicInfo = 0,
        FileStandardInfo = 1,
        FileNameInfo = 2,
        FileRenameInfo = 3,
        FileDispositionInfo = 4,
        FileAllocationInfo = 5,
        FileEndOfFileInfo = 6,
        FileStreamInfo = 7,
        FileCompressionInfo = 8,
        FileAttributeTagInfo = 9,
        FileIdBothDirectoryInfo = 10,
        FileIdBothDirectoryRestartInfo = 11,
        FileIoPriorityHintInfo = 12,
        FileRemoteProtocolInfo = 13,
        FileFullDirectoryInfo = 14,
        FileFullDirectoryRestartInfo = 15,
        FileStorageInfo = 16,
        FileAlignmentInfo = 17,
        FileIdInfo = 18,
        FileIdExtdDirectoryInfo = 19,
        FileIdExtdDirectoryRestartInfo = 20
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFileInformationByHandle(
        SafeFileHandle hFile,
        FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
        ref FILE_BASIC_INFO lpFileInformation,
        uint dwBufferSize
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
$tempDir = Join-Path $env:TEMP ("Sentra_AppB_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    $stageFile = Join-Path $tempDir "stage_app_b.tmp"
    $casBlob = Join-Path $tempDir "cas_app_b.blob"

    # 1. Open staging file with CREATE_NEW, GENERIC_READ | GENERIC_WRITE, share_mode(0)
    $hExclusive = [Win32ApproachB]::CreateFileW(
        $stageFile,
        [Win32ApproachB]::GENERIC_READ -bor [Win32ApproachB]::GENERIC_WRITE,
        0, # exclusive
        [IntPtr]::Zero,
        [Win32ApproachB]::CREATE_NEW,
        [Win32ApproachB]::FILE_ATTRIBUTE_NORMAL,
        [IntPtr]::Zero
    )
    $openOk = (-not $hExclusive.IsInvalid)
    $openErr = if (-not $openOk) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

    # 2. Write payload and flush
    $payload = [System.Text.Encoding]::UTF8.GetBytes("payload-approach-b-67890")
    $written = 0
    $writeOk = [Win32ApproachB]::WriteFile($hExclusive, $payload, [uint32]$payload.Length, [ref]$written, [IntPtr]::Zero)
    $flushOk = [Win32ApproachB]::FlushFileBuffers($hExclusive)

    # 3. Create destination hard link while exclusive handle is held
    $linkOk = [Win32ApproachB]::CreateHardLinkW($casBlob, $stageFile, [IntPtr]::Zero)
    $linkErr = if (-not $linkOk) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

    # 4. Call SetFileInformationByHandle(FileBasicInfo) via the open handle
    $basicInfo = New-Object Win32ApproachB+FILE_BASIC_INFO
    $basicInfo.CreationTime = 0   # 0 means do not change time
    $basicInfo.LastAccessTime = 0
    $basicInfo.LastWriteTime = 0
    $basicInfo.ChangeTime = 0
    $basicInfo.FileAttributes = [Win32ApproachB]::FILE_ATTRIBUTE_READONLY

    $structSize = [System.Runtime.InteropServices.Marshal]::SizeOf($basicInfo)
    $setInfoOk = [Win32ApproachB]::SetFileInformationByHandle(
        $hExclusive,
        [Win32ApproachB+FILE_INFO_BY_HANDLE_CLASS]::FileBasicInfo,
        [ref]$basicInfo,
        [uint32]$structSize
    )
    $setInfoErr = if (-not $setInfoOk) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

    # 5. Attempt write through original handle AFTER SetFileInformationByHandle
    $tamperBytes = [System.Text.Encoding]::UTF8.GetBytes("-tamper-held-b")
    $tamperWritten = 0
    $writeAfterSetInfo = [Win32ApproachB]::WriteFile($hExclusive, $tamperBytes, [uint32]$tamperBytes.Length, [ref]$tamperWritten, [IntPtr]::Zero)
    $writeAfterSetInfoErr = if (-not $writeAfterSetInfo) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

    # 6. Close handle
    $hExclusive.Close()

    # 7. Check attributes on disk for both links
    $stageAttrs = (Get-Item $stageFile).Attributes
    $dstAttrs = (Get-Item $casBlob).Attributes

    # 8. Attempt new writable opens on destination and staging
    $hNewDstWrite = [Win32ApproachB]::CreateFileW(
        $casBlob,
        [Win32ApproachB]::GENERIC_WRITE,
        1, # FILE_SHARE_READ
        [IntPtr]::Zero,
        [Win32ApproachB]::OPEN_EXISTING,
        [Win32ApproachB]::FILE_ATTRIBUTE_NORMAL,
        [IntPtr]::Zero
    )
    $dstWriteBlocked = $hNewDstWrite.IsInvalid
    $dstWriteErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if (-not $hNewDstWrite.IsInvalid) { $hNewDstWrite.Close() }

    $hNewStageWrite = [Win32ApproachB]::CreateFileW(
        $stageFile,
        [Win32ApproachB]::GENERIC_WRITE,
        1, # FILE_SHARE_READ
        [IntPtr]::Zero,
        [Win32ApproachB]::OPEN_EXISTING,
        [Win32ApproachB]::FILE_ATTRIBUTE_NORMAL,
        [IntPtr]::Zero
    )
    $stageWriteBlocked = $hNewStageWrite.IsInvalid
    $stageWriteErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if (-not $hNewStageWrite.IsInvalid) { $hNewStageWrite.Close() }

    $results["ApproachB_SetFileInformationByHandle"] = [ordered]@{
        OpenExclusiveSuccess = $openOk
        OpenExclusiveError = $openErr
        WriteInitialSuccess = $writeOk
        FlushSuccess = $flushOk
        HardLinkWhileOpenSuccess = $linkOk
        HardLinkError = $linkErr
        SetInfoByHandleSuccess = $setInfoOk
        SetInfoByHandleError = $setInfoErr
        WriteThroughOriginalHandleAfterSetInfo = $writeAfterSetInfo
        WriteThroughOriginalHandleError = $writeAfterSetInfoErr
        NewWritableOpenOnDstBlocked = $dstWriteBlocked
        NewWritableOpenOnDstError = $dstWriteErr # Expect 5 (ERROR_ACCESS_DENIED)
        NewWritableOpenOnStageBlocked = $stageWriteBlocked
        NewWritableOpenOnStageError = $stageWriteErr # Expect 5 (ERROR_ACCESS_DENIED)
        StageAttributes = $stageAttrs.ToString()
        DestinationAttributes = $dstAttrs.ToString()
        BothLinksReflectReadOnly = (($stageAttrs -band [IO.FileAttributes]::ReadOnly) -ne 0 -and ($dstAttrs -band [IO.FileAttributes]::ReadOnly) -ne 0)
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
