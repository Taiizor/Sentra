# Test: Zero-window exclusive lifecycle
# Location: experiments/phase1/filesystem-publication/test_exclusive_zero_window.ps1

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class Win32ZeroWin {
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
    public static extern bool ReadFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod
    );

    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint CREATE_NEW = 1;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    public const uint FILE_ATTRIBUTE_READONLY = 0x00000001;
    public const uint FILE_BEGIN = 0;
}
"@

$tempDir = Join-Path $env:TEMP ("Sentra_ZeroWin_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    $stageFile = Join-Path $tempDir "stage.tmp"
    $casBlob = Join-Path $tempDir "cas_zero_window.blob"

    # Step 1: Open with GENERIC_READ | GENERIC_WRITE, share_mode = 0 (exclusive)
    $hExclusive = [Win32ZeroWin]::CreateFileW(
        $stageFile,
        [Win32ZeroWin]::GENERIC_READ -bor [Win32ZeroWin]::GENERIC_WRITE,
        0, # SHARE_NONE
        [IntPtr]::Zero,
        [Win32ZeroWin]::CREATE_NEW,
        [Win32ZeroWin]::FILE_ATTRIBUTE_NORMAL,
        [IntPtr]::Zero
    )
    $createErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

    # Step 2: Write payload
    $payload = [Text.Encoding]::UTF8.GetBytes("zero-window-payload-content")
    $written = 0
    $writeOk = [Win32ZeroWin]::WriteFile($hExclusive, $payload, [uint32]$payload.Length, [ref]$written, [IntPtr]::Zero)

    # Step 3: Flush buffers
    $flushOk = [Win32ZeroWin]::FlushFileBuffers($hExclusive)

    # Step 4: Seek back to start and read back for hashing while holding exclusive lock!
    $newPtr = 0
    $seekOk = [Win32ZeroWin]::SetFilePointerEx($hExclusive, 0, [ref]$newPtr, [Win32ZeroWin]::FILE_BEGIN)
    $readBuf = New-Object byte[] ($payload.Length)
    $readBytes = 0
    $readOk = [Win32ZeroWin]::ReadFile($hExclusive, $readBuf, [uint32]$payload.Length, [ref]$readBytes, [IntPtr]::Zero)
    $readBackStr = [Text.Encoding]::UTF8.GetString($readBuf)

    # Step 5: External process attempts to open file while we hold it: MUST FAIL with Error 32!
    $extHandle = [Win32ZeroWin]::CreateFileW(
        $stageFile,
        [Win32ZeroWin]::GENERIC_READ,
        1, # FILE_SHARE_READ
        [IntPtr]::Zero,
        [Win32ZeroWin]::OPEN_EXISTING,
        [Win32ZeroWin]::FILE_ATTRIBUTE_NORMAL,
        [IntPtr]::Zero
    )
    $extErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $extBlocked = $extHandle.IsInvalid

    # Step 6: Create hard link to CAS destination WHILE HOLDING EXCLUSIVE HANDLE!
    $linkOk = [Win32ZeroWin]::CreateHardLinkW($casBlob, $stageFile, [IntPtr]::Zero)
    $linkErr = if (-not $linkOk) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

    # Step 7: Close exclusive handle
    $hExclusive.Close()

    # Step 8: Unlink staging name immediately
    [IO.File]::Delete($stageFile)
    $stagingGone = (-not (Test-Path $stageFile))

    # Step 9: Mark CAS destination read-only
    [Win32ZeroWin]::SetFileAttributesW($casBlob, [Win32ZeroWin]::FILE_ATTRIBUTE_READONLY) | Out-Null
    $casContent = [IO.File]::ReadAllText($casBlob)

    $result = [ordered]@{
        CreateExclusiveOk = (-not $hExclusive.IsInvalid)
        WriteOk = $writeOk
        FlushOk = $flushOk
        SeekAndReadOk = ($seekOk -and $readOk -and ($readBackStr -eq "zero-window-payload-content"))
        ExternalAccessBlocked = $extBlocked
        ExternalErrorCode = $extErr
        HardLinkWhileExclusiveOk = $linkOk
        HardLinkError = $linkErr
        StagingUnlinked = $stagingGone
        FinalCasBlobContent = $casContent
        FinalCasBlobReadOnly = (((Get-Item $casBlob).Attributes -band [IO.FileAttributes]::ReadOnly) -ne 0)
    }

    $result | ConvertTo-Json
} finally {
    if (Test-Path $tempDir) {
        Get-ChildItem -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $_.Attributes = [IO.FileAttributes]::Normal
        }
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
