# Increment 1.4: F-13-01 Approach C - Adversary Worker Process
# Location: experiments/phase1/filesystem-publication/f13_01_adversary_worker.ps1

param(
    [Parameter(Mandatory=$true)]
    [string]$StagingPath,

    [Parameter(Mandatory=$true)]
    [string]$DestinationPath,

    [Parameter(Mandatory=$true)]
    [string]$SyncPrefix,

    [Parameter(Mandatory=$true)]
    [string]$OutputPath
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class Win32AdvWorker {
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
    public static extern bool SetFileAttributesW(
        string lpFileName,
        uint dwFileAttributes
    );

    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 1;
    public const uint FILE_SHARE_WRITE = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
}
"@ -ErrorAction SilentlyContinue

$evt1Name = $SyncPrefix + "_LinkedHeld"
$evt2Name = $SyncPrefix + "_AttackedHeld"
$evt3Name = $SyncPrefix + "_Closed"

$evt1 = [System.Threading.EventWaitHandle]::OpenExisting($evt1Name)
$evt2 = [System.Threading.EventWaitHandle]::OpenExisting($evt2Name)
$evt3 = [System.Threading.EventWaitHandle]::OpenExisting($evt3Name)

$advResults = [ordered]@{}

# Wait for publisher to establish hard link while holding exclusive handle
$evt1.WaitOne() | Out-Null

# Attack Point 1: Try opening destination for write while publisher holds exclusive handle
$hDstHeld = [Win32AdvWorker]::CreateFileW(
    $DestinationPath,
    [Win32AdvWorker]::GENERIC_WRITE,
    [Win32AdvWorker]::FILE_SHARE_READ -bor [Win32AdvWorker]::FILE_SHARE_WRITE,
    [IntPtr]::Zero,
    [Win32AdvWorker]::OPEN_EXISTING,
    [Win32AdvWorker]::FILE_ATTRIBUTE_NORMAL,
    [IntPtr]::Zero
)
$dstHeldBlocked = $hDstHeld.IsInvalid
$dstHeldErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
if (-not $hDstHeld.IsInvalid) { $hDstHeld.Close() }

# Attack Point 2: Try opening staging path for write while publisher holds exclusive handle
$hStageHeld = [Win32AdvWorker]::CreateFileW(
    $StagingPath,
    [Win32AdvWorker]::GENERIC_WRITE,
    [Win32AdvWorker]::FILE_SHARE_READ -bor [Win32AdvWorker]::FILE_SHARE_WRITE,
    [IntPtr]::Zero,
    [Win32AdvWorker]::OPEN_EXISTING,
    [Win32AdvWorker]::FILE_ATTRIBUTE_NORMAL,
    [IntPtr]::Zero
)
$stageHeldBlocked = $hStageHeld.IsInvalid
$stageHeldErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
if (-not $hStageHeld.IsInvalid) { $hStageHeld.Close() }

# Attack Point 3: Try changing attributes while publication is in progress
$changeAttrWhileHeld = [Win32AdvWorker]::SetFileAttributesW($DestinationPath, [Win32AdvWorker]::FILE_ATTRIBUTE_NORMAL)
$changeAttrErr = if (-not $changeAttrWhileHeld) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

# Signal publisher that attack during held handle is complete
$evt2.Set() | Out-Null

# Wait for publisher to apply read-only, close exclusive handle, and unlink stage
$evt3.WaitOne() | Out-Null

# Attack Point 4: Try opening destination for write AFTER exclusive handle closed
$hDstClosed = [Win32AdvWorker]::CreateFileW(
    $DestinationPath,
    [Win32AdvWorker]::GENERIC_WRITE,
    [Win32AdvWorker]::FILE_SHARE_READ -bor [Win32AdvWorker]::FILE_SHARE_WRITE,
    [IntPtr]::Zero,
    [Win32AdvWorker]::OPEN_EXISTING,
    [Win32AdvWorker]::FILE_ATTRIBUTE_NORMAL,
    [IntPtr]::Zero
)
$dstClosedBlocked = $hDstClosed.IsInvalid
$dstClosedErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
if (-not $hDstClosed.IsInvalid) { $hDstClosed.Close() }

# Attack Point 5: Try hostile unprivileged attribute clearing (F-13-02 demonstration)
$clearReadOnlyAttempt = [Win32AdvWorker]::SetFileAttributesW($DestinationPath, [Win32AdvWorker]::FILE_ATTRIBUTE_NORMAL)
$clearReadOnlyErr = if (-not $clearReadOnlyAttempt) { [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }

# If cleared, can adversary now open for write?
$hDstAfterClear = [Win32AdvWorker]::CreateFileW(
    $DestinationPath,
    [Win32AdvWorker]::GENERIC_WRITE,
    [Win32AdvWorker]::FILE_SHARE_READ -bor [Win32AdvWorker]::FILE_SHARE_WRITE,
    [IntPtr]::Zero,
    [Win32AdvWorker]::OPEN_EXISTING,
    [Win32AdvWorker]::FILE_ATTRIBUTE_NORMAL,
    [IntPtr]::Zero
)
$dstAfterClearOpened = (-not $hDstAfterClear.IsInvalid)
if (-not $hDstAfterClear.IsInvalid) { $hDstAfterClear.Close() }

$advResults["AdversaryInterventions"] = [ordered]@{
    DestinationWriteBlockedDuringHeldHandle = $dstHeldBlocked
    DestinationWriteErrorDuringHeldHandle = $dstHeldErr # Expect 32 (ERROR_SHARING_VIOLATION)
    StagingWriteBlockedDuringHeldHandle = $stageHeldBlocked
    StagingWriteErrorDuringHeldHandle = $stageHeldErr # Expect 32 (ERROR_SHARING_VIOLATION)
    ChangeAttributesWhileHeld = $changeAttrWhileHeld
    ChangeAttributesWhileHeldError = $changeAttrErr
    DestinationWriteBlockedAfterClose = $dstClosedBlocked
    DestinationWriteErrorAfterClose = $dstClosedErr # Expect 5 (ERROR_ACCESS_DENIED)
    HostileSameUserClearReadOnlySucceeded = $clearReadOnlyAttempt
    HostileSameUserClearReadOnlyError = $clearReadOnlyErr
    WriteAccessAcquiredAfterHostileClear = $dstAfterClearOpened
}

$advResults | ConvertTo-Json | Set-Content -Path $OutputPath -Encoding UTF8
