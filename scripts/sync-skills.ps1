# Sentra AppSec Skills Synchronization & Update Tool
# Location: scripts/sync-skills.ps1
#
# Manages built-in AppSec cognitive skills in crates/sentra-core/assets/skills/
# using the dedicated lockfile: crates/sentra-core/assets/skills-lock.json
#
# Usage:
#   .\scripts\sync-skills.ps1                    # Installs/restores any missing security skills into assets/skills
#   .\scripts\sync-skills.ps1 -UpdateUpstream    # Fetches latest git commits from upstream GitHub repositories and updates assets/skills-lock.json
#   .\scripts\sync-skills.ps1 -Force             # Force re-installs all skills from lockfile into assets/skills
#   .\scripts\sync-skills.ps1 -DryRun            # Previews actions without modifying disk

param(
    [switch]$UpdateUpstream,
    [switch]$Force,
    [switch]$DryRun,
    [string[]]$Include = @(),
    [string[]]$Exclude = @()
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$AssetsDir = Join-Path $RepoRoot "crates/sentra-core/assets"
$LockFilePath = Join-Path $AssetsDir "skills-lock.json"
$AssetsSkillsDir = Join-Path $AssetsDir "skills"
$CatalogRsPath = Join-Path $RepoRoot "crates/sentra-core/src/skills/catalog.rs"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Sentra AppSec Skills Synchronizer & Updater" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Lockfile:      $LockFilePath"
Write-Host "Assets target: $AssetsSkillsDir"
Write-Host ""

if (-not (Test-Path $LockFilePath)) {
    Write-Error "Lockfile not found: $LockFilePath"
    exit 1
}

# Step 1: Parse crates/sentra-core/assets/skills-lock.json
$lockContent = Get-Content $LockFilePath -Raw | ConvertFrom-Json
$skillsMap = $lockContent.skills

if (-not $skillsMap) {
    Write-Error "No skills found in $LockFilePath."
    exit 1
}

$targetSkills = @()
foreach ($prop in $skillsMap.PSObject.Properties) {
    $id = $prop.Name
    if ($Exclude -contains $id) {
        continue
    }
    if ($Include.Count -gt 0 -and (-not ($Include -contains $id))) {
        continue
    }
    $targetSkills += [PSCustomObject]@{
        Id = $id
        Source = $prop.Value.source
        SkillPath = $prop.Value.skillPath
        ComputedHash = $prop.Value.computedHash
    }
}

Write-Host "Found $($targetSkills.Count) AppSec skills defined in assets/skills-lock.json." -ForegroundColor Green

# Check how many skills are currently missing from assets/skills
$missingSkills = @()
foreach ($s in $targetSkills) {
    $skillFile = Join-Path $AssetsSkillsDir (Join-Path $s.Id "SKILL.md")
    if (-not (Test-Path $skillFile)) {
        $missingSkills += $s.Id
    }
}

$needsDownload = $UpdateUpstream -or $Force -or ($missingSkills.Count -gt 0)

# Step 2: Download or update skills via isolated temporary staging
if ($needsDownload) {
    $tempStagingDir = Join-Path ([System.IO.Path]::GetTempPath()) "sentra-skills-staging-$([System.Guid]::NewGuid().ToString('N'))"
    
    if ($UpdateUpstream) {
        Write-Host ""
        Write-Host "Updating all skills to latest upstream GitHub commits..." -ForegroundColor Yellow
    } elseif ($Force) {
        Write-Host ""
        Write-Host "Force reinstalling all skills from lockfile..." -ForegroundColor Yellow
    } else {
        Write-Host ""
        Write-Host "Restoring $($missingSkills.Count) missing skill(s) from lockfile..." -ForegroundColor Yellow
    }
    Write-Host "Staging in isolated directory: $tempStagingDir" -ForegroundColor DarkGray

    if ($DryRun) {
        Write-Host "  [DryRun] Would execute download in staging area and copy to assets/skills/." -ForegroundColor Cyan
    } else {
        try {
            New-Item -ItemType Directory -Path $tempStagingDir -Force | Out-Null
            Copy-Item $LockFilePath (Join-Path $tempStagingDir "skills-lock.json")
            
            Push-Location $tempStagingDir
            try {
                if ($UpdateUpstream) {
                    bunx skills update -p -y
                } else {
                    bunx skills experimental_install
                }
            } finally {
                Pop-Location
            }

            # If updating upstream, copy the updated lockfile back to crates/sentra-core/assets/skills-lock.json
            $stagedLock = Join-Path $tempStagingDir "skills-lock.json"
            if ($UpdateUpstream -and (Test-Path $stagedLock)) {
                Copy-Item $stagedLock $LockFilePath -Force
                Write-Host "  [✓] Updated assets/skills-lock.json with new upstream hashes." -ForegroundColor Green
            }

            # Copy downloaded skills to crates/sentra-core/assets/skills
            $stagedSkillsDir = Join-Path $tempStagingDir ".agents/skills"
            if (Test-Path $stagedSkillsDir) {
                if (-not (Test-Path $AssetsSkillsDir)) {
                    New-Item -ItemType Directory -Path $AssetsSkillsDir -Force | Out-Null
                }
                foreach ($s in $targetSkills) {
                    $src = Join-Path $stagedSkillsDir $s.Id
                    $dst = Join-Path $AssetsSkillsDir $s.Id
                    if (Test-Path $src) {
                        if (-not (Test-Path $dst)) {
                            New-Item -ItemType Directory -Path $dst -Force | Out-Null
                        }
                        Copy-Item -Path "$src\*" -Destination $dst -Recurse -Force
                        Write-Host "  [✓] Synced: $($s.Id)" -ForegroundColor Green
                    } else {
                        Write-Warning "  [!] Could not locate staged skill: $($s.Id)"
                    }
                }
            }
        } finally {
            # Always clean up temporary staging directory
            if (Test-Path $tempStagingDir) {
                Remove-Item $tempStagingDir -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Cleaned up temporary staging area." -ForegroundColor DarkGray
            }
        }
    }
} else {
    Write-Host "All $($targetSkills.Count) skills are installed in assets/skills/." -ForegroundColor DarkGray
    Write-Host "Run with -UpdateUpstream to fetch newer versions from GitHub." -ForegroundColor DarkGray
}

# Step 3: Check catalog.rs registration
$catalogContent = ""
if (Test-Path $CatalogRsPath) {
    $catalogContent = Get-Content $CatalogRsPath -Raw
}

$unregisteredSkills = @()
foreach ($s in $targetSkills) {
    if ($catalogContent -and (-not ($catalogContent -match [regex]::Escape($s.Id)))) {
        $unregisteredSkills += $s
    }
}

if ($unregisteredSkills.Count -gt 0) {
    Write-Host ""
    Write-Host "NOTICE: $($unregisteredSkills.Count) skill(s) are present in lockfile but not yet referenced in catalog.rs:" -ForegroundColor Yellow
    foreach ($cand in $unregisteredSkills) {
        Write-Host "  - $($cand.Id) (Source: $($cand.Source))" -ForegroundColor Yellow
    }
    Write-Host "Add them to BUILTIN_SKILLS in $CatalogRsPath using:" -ForegroundColor Yellow
    $first = $unregisteredSkills[0]
    Write-Host @"
    SkillDefinition {
        id: "$($first.Id)",
        name: "$($first.Id -replace '-', ' ')",
        description: "AppSec cognitive playbook for $($first.Id).",
        category: SkillCategory::CodeReview,
        tags: &["$($first.Id)"],
        content: include_str!("../../assets/skills/$($first.Id)/SKILL.md"),
    },
"@ -ForegroundColor DarkGray
}

# Verification summary
$finalAssetsCount = 0
if (Test-Path $AssetsSkillsDir) {
    $finalAssetsCount = (Get-ChildItem $AssetsSkillsDir -Directory).Count
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host " Status Report" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "Active lockfile:                  crates/sentra-core/assets/skills-lock.json ($($targetSkills.Count) skills)" -ForegroundColor Green
Write-Host "Installed in assets/skills/:      $finalAssetsCount skills" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
