#Requires -Version 7.0
<#
.SYNOPSIS
    Verifies, restores, and updates the vendored agent skills embedded in sentra-core.

.DESCRIPTION
    Source of truth: crates/sentra-core/assets/skills-lock.json (skills CLI lock
    version 2 plus a Sentra "sentra" object per entry). Each entry pins:

      source        GitHub owner/repo
      ref           full commit SHA the skill folder was taken from
      skillPath     path of SKILL.md in that repository
      computedHash  skills CLI v2 content hash of the upstream skill folder
      sentra        license (SPDX id), licenseFile, upstreamLicensePath, and
                    vendoredFiles (files Sentra adds to the folder, such as the
                    repository LICENSE; they are excluded from computedHash)

    computedHash algorithm (vercel-labs/skills README, "Lock File Content Hash"):
    collect every file of the skill folder except metadata.json files and the
    .git, __pycache__, and __pypackages__ folders; use '/'-separated relative
    paths; replace CRLF with LF in text files (files without a NUL byte); sort
    by the UTF-8 bytes of the paths; feed path, NUL, decimal content length,
    NUL, content for each file into one SHA-256; take the lowercase hex digest.
    crates/sentra-core/src/skills/catalog.rs implements the same algorithm and
    its tests fail when the embedded files drift from the lock.

    Modes (all honor -Include/-Exclude; only the selected lock entries and
    skill directories are read or written):

      (default)        verify every selected skill; restore missing ones at the
                       locked ref; fail on local modifications
      -Force           re-fetch every selected skill at its locked ref
      -UpdateUpstream  move every selected skill to the current default-branch
                       commit of its source and record the new ref and hash
      -DryRun          verify and print the plan; no network, no writes
      -Prune           delete skill directories that have no lock entry

    Fetching uses the pinned skills CLI ($SkillsCliVersion) through bunx in a
    temporary staging directory with telemetry disabled. Restores at a locked
    ref run with --frozen-lockfile, so the CLI also checks computedHash. After
    staging, this script recomputes every hash itself before copying, mirrors
    each skill directory (files removed upstream are removed here), adds the
    upstream LICENSE when the skill folder has none, and rewrites only the
    selected lock entries (atomically, LF, trailing newline).

    Exit codes: 0 success, 1 verification failure, 2 usage error,
    3 skills CLI or network failure.

.EXAMPLE
    ./scripts/sync-skills.ps1 -DryRun
.EXAMPLE
    ./scripts/sync-skills.ps1 -UpdateUpstream -Include golang-security
#>
[CmdletBinding()]
param(
    [switch]$UpdateUpstream,
    [switch]$Force,
    [switch]$DryRun,
    [switch]$Prune,
    [string[]]$Include = @(),
    [string[]]$Exclude = @(),
    # Overrides for testing against a copy of the assets.
    [string]$AssetsDir = '',
    [string]$StagingRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Accept both `-Include a,b` (PowerShell array) and `-Include "a,b"` (pwsh -File).
$Include = @($Include | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$Exclude = @($Exclude | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# Pinned skills CLI (npm package "skills", MIT, vercel-labs/skills). 1.8.0 is
# the first release that reads and writes lock version 2. npm versions are
# immutable; bump deliberately and re-run the verification.
$SkillsCliVersion = '1.8.0'
$LockVersion = 2
$ExcludedFiles = @('metadata.json')
$ExcludedDirs = @('.git', '__pycache__', '__pypackages__')
$LicenseNames = @('LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENCE', 'LICENCE.md', 'LICENCE.txt', 'COPYING', 'COPYING.md', 'COPYING.txt')

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $AssetsDir) { $AssetsDir = Join-Path $RepoRoot 'crates/sentra-core/assets' }
$AssetsDir = (Resolve-Path $AssetsDir).Path
$LockFilePath = Join-Path $AssetsDir 'skills-lock.json'
$SkillsDir = Join-Path $AssetsDir 'skills'
$CatalogRsPath = Join-Path $RepoRoot 'crates/sentra-core/src/skills/catalog.rs'
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Stop-Sync([int]$Code, [string]$Message) {
    # Thrown (not exit) so cleanup in finally blocks always runs.
    $failure = [System.Exception]::new($Message)
    $failure.Data['SyncExitCode'] = $Code
    throw $failure
}

# --- skills CLI v2 content hash ------------------------------------------------

function Get-NormalizedContent([byte[]]$Bytes) {
    if ([Array]::IndexOf($Bytes, [byte]0) -ge 0) { return , $Bytes }
    $latin1 = [System.Text.Encoding]::Latin1
    $text = $latin1.GetString($Bytes)
    if (-not $text.Contains("`r`n")) { return , $Bytes }
    return , $latin1.GetBytes($text.Replace("`r`n", "`n"))
}

function Get-SkillFolderFiles([string]$Dir) {
    # Returns @{ Path = 'rel/path'; FullName = '...' } for every hashed file.
    $result = [System.Collections.Generic.List[object]]::new()
    $pending = [System.Collections.Generic.Stack[object]]::new()
    $pending.Push(@($Dir, ''))
    while ($pending.Count -gt 0) {
        $current, $prefix = $pending.Pop()
        foreach ($item in Get-ChildItem -LiteralPath $current -Force) {
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Symlinks are not supported in vendored skills: $($item.FullName)"
            }
            if ($item.PSIsContainer) {
                if ($ExcludedDirs -contains $item.Name) { continue }
                $pending.Push(@($item.FullName, "$prefix$($item.Name)/"))
            } elseif ($ExcludedFiles -notcontains $item.Name) {
                $result.Add(@{ Path = "$prefix$($item.Name)"; FullName = $item.FullName })
            }
        }
    }
    return $result.ToArray()
}

function Get-SkillFolderHash([object[]]$Files) {
    # $Files: @{ Path; Bytes } entries.
    # Hex of the UTF-8 path bytes compares ordinally exactly like the bytes.
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($file in $Files) {
        $items.Add([pscustomobject]@{
                Key   = [Convert]::ToHexString([System.Text.Encoding]::UTF8.GetBytes($file.Path))
                Path  = $file.Path
                Bytes = $file.Bytes
            })
    }
    $items.Sort([System.Comparison[object]] { param($a, $b) [string]::CompareOrdinal($a.Key, $b.Key) })
    $hash = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $nul = [byte[]]@(0)
    foreach ($file in $items) {
        $content = Get-NormalizedContent $file.Bytes
        $hash.AppendData([System.Text.Encoding]::UTF8.GetBytes($file.Path))
        $hash.AppendData($nul)
        $hash.AppendData([System.Text.Encoding]::ASCII.GetBytes([string]$content.Length))
        $hash.AppendData($nul)
        $hash.AppendData($content)
    }
    return [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
}

function Get-DirectoryHash([string]$Dir, [string[]]$Skip = @()) {
    $files = foreach ($f in Get-SkillFolderFiles $Dir) {
        if ($Skip -contains $f.Path) { continue }
        @{ Path = $f.Path; Bytes = [System.IO.File]::ReadAllBytes($f.FullName) }
    }
    return Get-SkillFolderHash @($files)
}

function Test-HashSelf {
    $vectors = @(
        @{ Files = @(); Want = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
        @{ Files = @(@{ Path = 'SKILL.md'; Bytes = [System.Text.Encoding]::UTF8.GetBytes("# hi`n") }); Want = '93c36952d8843b33e68ae970ebabcc03e1687c9bb0dd1ecaf357060318952f55' },
        @{ Files = @(@{ Path = 'docs/b.md'; Bytes = [System.Text.Encoding]::UTF8.GetBytes("b`r`n") }, @{ Path = 'SKILL.md'; Bytes = [System.Text.Encoding]::UTF8.GetBytes("a`n") }); Want = 'b22c4d22aa319d2924312fa18fcbfedc88fa89c74dbd8f298c683e1caf7b7f24' }
    )
    foreach ($v in $vectors) {
        $got = Get-SkillFolderHash @($v.Files)
        if ($got -ne $v.Want) { Stop-Sync 1 "content hash self-test failed: expected $($v.Want), got $got" }
    }
}

# --- licenses -------------------------------------------------------------------

function Get-LicenseId([string]$Text) {
    if ($Text.Contains('Permission is hereby granted, free of charge, to any person obtaining a copy')) { return 'MIT' }
    if ($Text.Contains('Apache License') -and $Text.Contains('Version 2.0, January 2004')) { return 'Apache-2.0' }
    return $null
}

function Get-UpstreamLicense([string]$Source, [string]$Ref, [string]$WorkDir) {
    # Repository root license at the pinned commit, downloaded byte-for-byte.
    foreach ($name in $LicenseNames) {
        $uri = "https://raw.githubusercontent.com/$Source/$Ref/$name"
        $file = Join-Path $WorkDir "license-$([guid]::NewGuid().ToString('N'))"
        try {
            Invoke-WebRequest -Uri $uri -OutFile $file -ErrorAction Stop | Out-Null
        } catch {
            continue
        }
        return @{ Name = $name; Bytes = [System.IO.File]::ReadAllBytes($file) }
    }
    return $null
}

# --- lock file ------------------------------------------------------------------

function ConvertTo-JsonString([string]$Value) {
    return ($Value | ConvertTo-Json -Compress)
}

function Write-LockFile([System.Collections.IDictionary]$Skills, [string]$Path) {
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("{`n  `"version`": $LockVersion,`n  `"skills`": {")
    $ids = [string[]]@($Skills.Keys)
    [Array]::Sort($ids, [System.StringComparer]::Ordinal)
    for ($i = 0; $i -lt $ids.Count; $i++) {
        $e = $Skills[$ids[$i]]
        $s = $e.sentra
        [void]$sb.Append("`n    $(ConvertTo-JsonString $ids[$i]): {")
        foreach ($key in 'source', 'ref', 'sourceType', 'skillPath', 'computedHash') {
            [void]$sb.Append("`n      `"$key`": $(ConvertTo-JsonString ([string]$e[$key])),")
        }
        [void]$sb.Append("`n      `"sentra`": {")
        foreach ($key in 'license', 'licenseFile', 'upstreamLicensePath') {
            [void]$sb.Append("`n        `"$key`": $(ConvertTo-JsonString ([string]$s[$key])),")
        }
        $vendored = @($s['vendoredFiles'])
        if ($vendored.Count -eq 0) {
            [void]$sb.Append("`n        `"vendoredFiles`": []")
        } else {
            $quoted = ($vendored | ForEach-Object { "`n          $(ConvertTo-JsonString ([string]$_))" }) -join ','
            [void]$sb.Append("`n        `"vendoredFiles`": [$quoted`n        ]")
        }
        [void]$sb.Append("`n      }`n    }")
        if ($i -lt $ids.Count - 1) { [void]$sb.Append(',') }
    }
    [void]$sb.Append("`n  }`n}`n")
    $tmp = "$Path.tmp-$PID"
    [System.IO.File]::WriteAllText($tmp, $sb.ToString(), $Utf8NoBom)
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

# --- main -----------------------------------------------------------------------

function Invoke-SkillSync {
    Test-HashSelf

    if ($UpdateUpstream -and $Force) { Stop-Sync 2 '-UpdateUpstream and -Force are mutually exclusive.' }
    if (-not (Test-Path -LiteralPath $LockFilePath)) { Stop-Sync 2 "lock file not found: $LockFilePath" }

    $lock = Get-Content -LiteralPath $LockFilePath -Raw | ConvertFrom-Json -AsHashtable
    if ($lock.version -ne $LockVersion) { Stop-Sync 2 "expected lock version $LockVersion in $LockFilePath, found $($lock.version)." }
    $entries = $lock.skills
    if (-not $entries -or $entries.Count -eq 0) { Stop-Sync 2 "no skills in $LockFilePath." }

    foreach ($name in @($Include) + @($Exclude)) {
        if (-not $entries.Contains($name)) { Stop-Sync 2 "unknown skill '$name' in -Include/-Exclude (not in the lock)." }
    }
    $selected = @($entries.Keys | Where-Object {
            ($Include.Count -eq 0 -or $Include -contains $_) -and ($Exclude -notcontains $_)
        } | Sort-Object)
    if ($selected.Count -eq 0) { Stop-Sync 2 'the -Include/-Exclude filters select no skills.' }

    Write-Host "Lock file: $LockFilePath (version $LockVersion, $($entries.Count) skills, $($selected.Count) selected)"
    Write-Host "Skills:    $SkillsDir"

    # 1. Verify local state.
    $missing = [System.Collections.Generic.List[string]]::new()
    $modified = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $selected) {
        $e = $entries[$id]
        foreach ($key in 'source', 'ref', 'sourceType', 'skillPath', 'computedHash') {
            if (-not $e[$key]) { Stop-Sync 1 "$id has no '$key' in the lock." }
        }
        if ($e.ref -notmatch '^[0-9a-f]{40}$') { Stop-Sync 1 "$id ref '$($e.ref)' is not a full commit SHA." }
        if (-not $e.sentra) { Stop-Sync 1 "$id has no 'sentra' license record in the lock." }
        $dir = Join-Path $SkillsDir $id
        if (-not (Test-Path -LiteralPath (Join-Path $dir 'SKILL.md'))) { $missing.Add($id); continue }
        $vendored = @($e.sentra.vendoredFiles)
        $actual = Get-DirectoryHash $dir $vendored
        $licensePresent = Test-Path -LiteralPath (Join-Path $dir $e.sentra.licenseFile)
        if ($actual -ne $e.computedHash -or -not $licensePresent) {
            $modified.Add($id)
            Write-Host "  [modified] $id (hash $actual, lock $($e.computedHash), license file present: $licensePresent)" -ForegroundColor Yellow
        } else {
            Write-Host "  [ok]       $id" -ForegroundColor DarkGray
        }
    }
    foreach ($id in $missing) { Write-Host "  [missing]  $id" -ForegroundColor Yellow }

    $orphans = @()
    if (Test-Path -LiteralPath $SkillsDir) {
        $orphans = @(Get-ChildItem -LiteralPath $SkillsDir -Directory | Where-Object { -not $entries.Contains($_.Name) } | ForEach-Object Name)
    }
    foreach ($id in $orphans) { Write-Host "  [orphan]   $id (no lock entry)" -ForegroundColor Yellow }

    # 2. Plan.
    $toFetch = @(if ($UpdateUpstream -or $Force) { $selected } else { $missing })
    if (-not $UpdateUpstream -and -not $Force -and $modified.Count -gt 0) {
        Stop-Sync 1 "$($modified.Count) skill(s) differ from the lock: $($modified -join ', '). Re-run with -Force to restore the locked content, or -UpdateUpstream to move to new upstream commits."
    }
    if ($orphans.Count -gt 0 -and -not $Prune) {
        Stop-Sync 1 "skill directories without a lock entry: $($orphans -join ', '). Add lock entries or re-run with -Prune to delete them."
    }

    if ($DryRun) {
        if ($toFetch.Count -gt 0) {
            $mode = if ($UpdateUpstream) { 'update to the latest upstream commit' } else { 'fetch at the locked ref' }
            Write-Host "[DryRun] Would $mode with skills@${SkillsCliVersion}: $($toFetch -join ', ')" -ForegroundColor Cyan
        }
        foreach ($id in $orphans) { Write-Host "[DryRun] Would delete orphan directory $id" -ForegroundColor Cyan }
        if ($toFetch.Count -eq 0 -and $orphans.Count -eq 0) { Write-Host 'Everything matches the lock.' -ForegroundColor Green }
        return
    }

    # 3. Fetch into staging with the pinned skills CLI.
    $updated = [ordered]@{}
    if ($toFetch.Count -gt 0) {
        if (-not (Get-Command bunx -ErrorAction SilentlyContinue)) { Stop-Sync 3 'bunx (Bun) is required to run the pinned skills CLI.' }
        if (-not $StagingRoot) { $StagingRoot = [System.IO.Path]::GetTempPath() }
        $staging = Join-Path $StagingRoot "sentra-skills-staging-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $staging | Out-Null
        try {
            $newRefs = @{}
            if ($UpdateUpstream) {
                foreach ($source in @($toFetch | ForEach-Object { $entries[$_].source } | Sort-Object -Unique)) {
                    $output = @(git ls-remote "https://github.com/$source.git" HEAD 2>$null)
                    $gitExit = $LASTEXITCODE
                    $head = if ($output.Count -gt 0) { [string]$output[0] } else { '' }
                    if ($gitExit -ne 0 -or -not ($head -match '^([0-9a-f]{40})\s+HEAD$')) {
                        Stop-Sync 3 "cannot resolve the default-branch commit of $source."
                    }
                    $newRefs[$source] = $Matches[1]
                    Write-Host "  $source -> $($newRefs[$source])"
                }
            }
            $stagingSkills = [ordered]@{}
            foreach ($id in $toFetch) {
                $e = $entries[$id]
                $stagingSkills[$id] = [ordered]@{
                    source       = $e.source
                    ref          = if ($UpdateUpstream) { $newRefs[$e.source] } else { $e.ref }
                    sourceType   = $e.sourceType
                    skillPath    = $e.skillPath
                    computedHash = if ($UpdateUpstream) { '' } else { $e.computedHash }
                }
            }
            $stagingLock = [ordered]@{ version = $LockVersion; skills = $stagingSkills } | ConvertTo-Json -Depth 5
            [System.IO.File]::WriteAllText((Join-Path $staging 'skills-lock.json'), "$stagingLock`n", $Utf8NoBom)

            $frozen = if ($UpdateUpstream) { '--no-frozen-lockfile' } else { '--frozen-lockfile' }
            $savedTelemetry = $env:DISABLE_TELEMETRY, $env:DO_NOT_TRACK
            $env:DISABLE_TELEMETRY = '1'
            $env:DO_NOT_TRACK = '1'
            Push-Location $staging
            try {
                & bunx --bun "skills@$SkillsCliVersion" experimental_install --agent universal $frozen
                $cliExit = $LASTEXITCODE
            } finally {
                Pop-Location
                $env:DISABLE_TELEMETRY, $env:DO_NOT_TRACK = $savedTelemetry
            }
            if ($cliExit -ne 0) { Stop-Sync 3 "skills@$SkillsCliVersion experimental_install exited with $cliExit." }

            $stagedLock = Get-Content -LiteralPath (Join-Path $staging 'skills-lock.json') -Raw | ConvertFrom-Json -AsHashtable
            foreach ($id in $toFetch) {
                $src = Join-Path $staging ".agents/skills/$id"
                if (-not (Test-Path -LiteralPath (Join-Path $src 'SKILL.md'))) { Stop-Sync 3 "the skills CLI did not restore $id." }
                $ref = $stagingSkills[$id].ref
                $hash = Get-DirectoryHash $src
                if ($UpdateUpstream) {
                    $cliHash = $stagedLock.skills[$id].computedHash
                    if ($hash -ne $cliHash) { Stop-Sync 1 "$id hash mismatch: computed $hash, skills CLI recorded $cliHash." }
                } elseif ($hash -ne $entries[$id].computedHash) {
                    Stop-Sync 1 "$id fetched at $ref does not match the lock (computed $hash, lock $($entries[$id].computedHash))."
                }

                # License: prefer the skill folder's own license file, else the
                # repository's root license at the same commit.
                $own = @(Get-ChildItem -LiteralPath $src -File | Where-Object { $LicenseNames -contains $_.Name } | Sort-Object Name)
                $vendored = @()
                if ($own.Count -gt 0) {
                    $licenseFile = $own[0].Name
                    $licenseBytes = [System.IO.File]::ReadAllBytes($own[0].FullName)
                    $skillDir = $entries[$id].skillPath -replace '/SKILL\.md$', ''
                    $upstreamLicensePath = "$skillDir/$licenseFile"
                } else {
                    $license = Get-UpstreamLicense $entries[$id].source $ref $staging
                    if (-not $license) { Stop-Sync 1 "$id has no discoverable license in $($entries[$id].source)@$ref; do not bundle it without a license review." }
                    $licenseFile = 'LICENSE'
                    $licenseBytes = Get-NormalizedContent $license.Bytes
                    $upstreamLicensePath = $license.Name
                    [System.IO.File]::WriteAllBytes((Join-Path $src $licenseFile), $licenseBytes)
                    $vendored = @($licenseFile)
                }
                $spdx = Get-LicenseId ([System.Text.Encoding]::UTF8.GetString($licenseBytes))
                if (-not $spdx) { Stop-Sync 1 "$id license ($upstreamLicensePath) is neither MIT nor Apache-2.0; review it manually before bundling." }

                $updated[$id] = [ordered]@{
                    source       = $entries[$id].source
                    ref          = $ref
                    sourceType   = $entries[$id].sourceType
                    skillPath    = $entries[$id].skillPath
                    computedHash = $hash
                    sentra       = [ordered]@{
                        license             = $spdx
                        licenseFile         = $licenseFile
                        upstreamLicensePath = $upstreamLicensePath
                        vendoredFiles       = $vendored
                    }
                }
            }

            # 4. Mirror each fetched skill directory (remove, then copy).
            foreach ($id in $toFetch) {
                $src = Join-Path $staging ".agents/skills/$id"
                $dst = Join-Path $SkillsDir $id
                $tmp = Join-Path $SkillsDir ".sync-$id-$PID"
                if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
                New-Item -ItemType Directory -Path $tmp | Out-Null
                foreach ($f in Get-SkillFolderFiles $src) {
                    $target = Join-Path $tmp $f.Path
                    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
                    $bytes = Get-NormalizedContent ([System.IO.File]::ReadAllBytes($f.FullName))
                    [System.IO.File]::WriteAllBytes($target, $bytes)
                }
                $check = Get-DirectoryHash $tmp @($updated[$id].sentra.vendoredFiles)
                if ($check -ne $updated[$id].computedHash) { Stop-Sync 1 "$id changed while copying (hash $check)." }
                if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Recurse -Force }
                Move-Item -LiteralPath $tmp -Destination $dst
                Write-Host "  [synced]   $id @ $($updated[$id].ref)" -ForegroundColor Green
            }
        } finally {
            if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
            Get-ChildItem -LiteralPath $SkillsDir -Directory -Force -Filter ".sync-*-$PID" -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($id in $orphans) {
        Remove-Item -LiteralPath (Join-Path $SkillsDir $id) -Recurse -Force
        Write-Host "  [deleted]  $id (no lock entry)" -ForegroundColor Yellow
    }

    # 5. Rewrite only the selected lock entries that changed.
    $changed = @($updated.Keys | Where-Object {
            $old = $entries[$_]
            $new = $updated[$_]
            $old.ref -ne $new.ref -or $old.computedHash -ne $new.computedHash -or
            $old.sentra.license -ne $new.sentra.license -or $old.sentra.licenseFile -ne $new.sentra.licenseFile -or
            $old.sentra.upstreamLicensePath -ne $new.sentra.upstreamLicensePath -or
            (@($old.sentra.vendoredFiles) -join '|') -ne (@($new.sentra.vendoredFiles) -join '|')
        })
    if ($changed.Count -gt 0) {
        $merged = [ordered]@{}
        foreach ($id in $entries.Keys) { $merged[$id] = if ($updated.Contains($id)) { $updated[$id] } else { $entries[$id] } }
        Write-LockFile $merged $LockFilePath
        Write-Host "Updated lock entries: $($changed -join ', ')" -ForegroundColor Green
        Write-Host 'Update NOTICE (commit, license, copyright per source) to match; the sentra-core catalog tests enforce it:' -ForegroundColor Yellow
        foreach ($id in $changed) { Write-Host "  $id -> https://github.com/$($updated[$id].source) @ $($updated[$id].ref) ($($updated[$id].sentra.license))" -ForegroundColor Yellow }
    }

    # 6. Catalog registration (BUILTIN_SKILLS must list every skill directory).
    if (Test-Path -LiteralPath $CatalogRsPath) {
        $catalog = Get-Content -LiteralPath $CatalogRsPath -Raw
        $unregistered = @($entries.Keys | Where-Object { -not $catalog.Contains("id: `"$_`",") } | Sort-Object)
        if ($unregistered.Count -gt 0) {
            Write-Host "Add these skills to BUILTIN_SKILLS in ${CatalogRsPath}:" -ForegroundColor Yellow
            foreach ($id in $unregistered) {
                Write-Host "    builtin_skill! {`n        id: `"$id`",`n        name: `"<display title>`",`n        category: SkillCategory::CodeReview,`n        tags: [`"$id`"],`n    }," -ForegroundColor DarkGray
            }
            Stop-Sync 1 "$($unregistered.Count) skill(s) are not registered in BUILTIN_SKILLS."
        }
    }

    Write-Host 'Done. Run: cargo test -p sentra-core skills::catalog' -ForegroundColor Green
}

try {
    Invoke-SkillSync
    exit 0
} catch {
    $code = $_.Exception.Data['SyncExitCode']
    if ($null -eq $code) { $code = 1 }
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit $code
}
