# Process Termination Worker
# Location: experiments/phase1/filesystem-publication/termination_worker.ps1

param(
    [Parameter(Mandatory=$true)]
    [int]$StopBoundary,

    [Parameter(Mandatory=$true)]
    [string]$StagingDir,

    [Parameter(Mandatory=$true)]
    [string]$BlobDir
)

$srcPath = Join-Path $StagingDir "content.tmp"
$dstPath = Join-Path $BlobDir "terminated_test.blob"

# Boundary 1: Before source creation
if ($StopBoundary -eq 1) {
    [System.Diagnostics.Process]::GetCurrentProcess().Kill()
}

# Boundary 2: During source writing (partial write, unbuffered, killed)
$fs = [System.IO.File]::OpenWrite($srcPath)
$partial = [System.Text.Encoding]::UTF8.GetBytes("partial-chunk-")
$fs.Write($partial, 0, $partial.Length)
if ($StopBoundary -eq 2) {
    [System.Diagnostics.Process]::GetCurrentProcess().Kill()
}

# Boundary 3: Complete write + flush, killed before link
$full = [System.Text.Encoding]::UTF8.GetBytes("completed-payload-bytes")
$fs.Write($full, 0, $full.Length)
$fs.Flush()
$fs.Close()
if ($StopBoundary -eq 3) {
    [System.Diagnostics.Process]::GetCurrentProcess().Kill()
}

# Boundary 4: Read-back verified, killed immediately before CreateHardLinkW
$readBytes = [System.IO.File]::ReadAllBytes($srcPath)
if ($StopBoundary -eq 4) {
    [System.Diagnostics.Process]::GetCurrentProcess().Kill()
}

# Boundary 5: CreateHardLinkW succeeds, killed immediately after publication
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32Term {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateHardLinkW(string lpFileName, string lpExistingFileName, IntPtr lpSecurityAttributes);
}
"@ -ErrorAction SilentlyContinue

$linkOk = [Win32Term]::CreateHardLinkW($dstPath, $srcPath, [IntPtr]::Zero)
if ($StopBoundary -eq 5) {
    [System.Diagnostics.Process]::GetCurrentProcess().Kill()
}

# Boundary 6: Before staging name cleanup
if ($StopBoundary -eq 6) {
    [System.Diagnostics.Process]::GetCurrentProcess().Kill()
}

# Boundary 7: After staging name cleanup
[System.IO.File]::Delete($srcPath)
if ($StopBoundary -eq 7) {
    [System.Diagnostics.Process]::GetCurrentProcess().Kill()
}
