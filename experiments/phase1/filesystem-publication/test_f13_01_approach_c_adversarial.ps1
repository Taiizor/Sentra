# Increment 1.4: F-13-01 Approach C - Adversarial Independent Process Test Controller
# Location: experiments/phase1/filesystem-publication/test_f13_01_approach_c_adversarial.ps1

$adversaryScript = Join-Path $PSScriptRoot "f13_01_adversary_worker.ps1"
if (-not (Test-Path $adversaryScript)) {
    throw "Adversary script not found: $adversaryScript"
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class Win32AdvPublisher {
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
    public const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    public const uint FILE_ATTRIBUTE_READONLY = 0x00000001;
}
"@ -ErrorAction SilentlyContinue

$guid = [Guid]::NewGuid().ToString("N")
$syncPrefix = "SentraSync_" + $guid
$tempDir = Join-Path $env:TEMP ("Sentra_AdvTest_" + $guid)
New-Item -ItemType Directory -Path $tempDir | Out-Null

$evt1 = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::ManualReset, ($syncPrefix + "_LinkedHeld"))
$evt2 = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::ManualReset, ($syncPrefix + "_AttackedHeld"))
$evt3 = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::ManualReset, ($syncPrefix + "_Closed"))

$stagePath = Join-Path $tempDir "stage_adversarial.tmp"
$dstPath = Join-Path $tempDir "cas_adversarial.blob"
$advOutputPath = Join-Path $tempDir "adversary_output.json"

try {
    # 1. Spawn independent adversary process in background
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "pwsh"
    $psi.Arguments = "-NoProfile -File `"$adversaryScript`" -StagingPath `"$stagePath`" -DestinationPath `"$dstPath`" -SyncPrefix `"$syncPrefix`" -OutputPath `"$advOutputPath`""
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $advProc = [System.Diagnostics.Process]::Start($psi)

    # 2. Publisher creates staging file exclusively with CREATE_NEW, share_mode(0)
    $hExclusive = [Win32AdvPublisher]::CreateFileW(
        $stagePath,
        [Win32AdvPublisher]::GENERIC_READ -bor [Win32AdvPublisher]::GENERIC_WRITE,
        0, # share_mode(0)
        [IntPtr]::Zero,
        [Win32AdvPublisher]::CREATE_NEW,
        [Win32AdvPublisher]::FILE_ATTRIBUTE_NORMAL,
        [IntPtr]::Zero
    )

    # 3. Write payload and flush
    $payload = [System.Text.Encoding]::UTF8.GetBytes("adversarial-verified-payload-12345")
    $written = 0
    [Win32AdvPublisher]::WriteFile($hExclusive, $payload, [uint32]$payload.Length, [ref]$written, [IntPtr]::Zero) | Out-Null
    [Win32AdvPublisher]::FlushFileBuffers($hExclusive) | Out-Null

    # 4. Create hard link to destination while exclusive handle is STILL OPEN
    [Win32AdvPublisher]::CreateHardLinkW($dstPath, $stagePath, [IntPtr]::Zero) | Out-Null

    # 5. Signal adversary that link exists but handle is still open
    $evt1.Set() | Out-Null

    # 6. Wait for adversary to attempt attack while handle is held
    $evt2.WaitOne(10000) | Out-Null

    # Sequence under test:
    # Close exclusive handle first (releases lock)
    $hExclusive.Close()

    # Delete staging path
    [System.IO.File]::Delete($stagePath)

    # Apply ReadOnly attribute to destination
    [Win32AdvPublisher]::SetFileAttributesW($dstPath, [Win32AdvPublisher]::FILE_ATTRIBUTE_READONLY) | Out-Null

    # 9. Signal adversary that handle is closed and staging unlinked
    $evt3.Set() | Out-Null

    # 10. Wait for adversary process to exit
    $advProc.WaitForExit(10000) | Out-Null
    $advExitCode = $advProc.ExitCode
    $advProc.Dispose()

    # 11. Read adversary output
    $advJson = if (Test-Path $advOutputPath) { Get-Content -Raw $advOutputPath } else { "{}" }

    $publisherResult = [ordered]@{}
    $publisherResult["PublisherSummary"] = [ordered]@{
        AdversaryExitCode = $advExitCode
        StagingFileRemoved = (-not (Test-Path $stagePath))
        DestinationFileExists = (Test-Path $dstPath)
        FinalBlobLength = if (Test-Path $dstPath) { (Get-Item $dstPath).Length } else { 0 }
    }
    $publisherResult["AdversaryReport"] = ($advJson | ConvertFrom-Json)

    $publisherResult | ConvertTo-Json -Depth 5
} finally {
    $evt1.Dispose()
    $evt2.Dispose()
    $evt3.Dispose()

    if (Test-Path $tempDir) {
        Get-ChildItem -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $_.Attributes = [IO.FileAttributes]::Normal
        }
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
