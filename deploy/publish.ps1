[CmdletBinding()]
param(
    [string]$Message = "",
    [string]$Branch = "master",
    [switch]$NoPush,
    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$MaximumGitFileBytes = 95MB

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )
    Write-Host "`n==> $Label" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Require-Command {
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

Set-Location -LiteralPath $ProjectRoot

Require-Command "git"
Require-Command "python"
Require-Command "npm.cmd"

$CurrentBranch = (& git branch --show-current).Trim()
if ($LASTEXITCODE -ne 0 -or $CurrentBranch -ne $Branch) {
    throw "Expected branch '$Branch', current branch is '$CurrentBranch'"
}

Invoke-Checked "Fetch origin/$Branch" {
    git fetch origin $Branch
}

$BehindCount = [int]((& git rev-list --count "HEAD..origin/$Branch").Trim())
if ($BehindCount -gt 0) {
    throw "Local branch is behind origin/$Branch by $BehindCount commit(s). Pull and review first."
}

Invoke-Checked "Compile Python sources" {
    python -m compileall -q `
        backend/api `
        backend/services `
        backend/tests `
        backend/migrations `
        backend/app.py `
        backend/config.py `
        backend/database.py `
        scripts `
        wsgi.py
}

$TestTemp = Join-Path $ProjectRoot ".test-tmp"
try {
    Invoke-Checked "Run backend tests" {
        python -m pytest backend/tests -q `
            -p no:cacheprovider `
            --basetemp $TestTemp
    }
}
finally {
    if (Test-Path -LiteralPath $TestTemp) {
        Remove-Item -LiteralPath $TestTemp -Recurse -Force
    }
}

Push-Location -LiteralPath (Join-Path $ProjectRoot "frontend")
try {
    Invoke-Checked "Install frontend dependencies from package-lock.json" {
        npm.cmd ci
    }
    Invoke-Checked "Audit frontend dependencies" {
        npm.cmd audit --audit-level=low
    }
    Invoke-Checked "Run frontend unit tests" {
        npm.cmd test
    }
    Invoke-Checked "Build frontend/dist" {
        npm.cmd run build
    }
}
finally {
    Pop-Location
}

$RequiredArtifacts = @(
    "frontend/dist/index.html",
    "backend/data/analysis_store.db",
    "backend/uploads/incident"
)
foreach ($RelativePath in $RequiredArtifacts) {
    if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot $RelativePath))) {
        throw "Required release artifact is missing: $RelativePath"
    }
}

Invoke-Checked "Verify SQLite queue and committed evidence" {
    python scripts/verify_test_seed.py
}

$EvidenceFiles = Get-ChildItem `
    -LiteralPath (Join-Path $ProjectRoot "backend/uploads/incident") `
    -Recurse -File
if ($EvidenceFiles.Count -eq 0) {
    throw "No test images, attachments, or logs were found"
}

Invoke-Checked "Check Git whitespace errors" {
    git diff --check
}

if ($ValidateOnly) {
    Write-Host "`nPublish validation completed; no files were staged, committed, or pushed." -ForegroundColor Green
    exit 0
}

Invoke-Checked "Stage source, frontend build, seed database, and test evidence" {
    git add -A
}

$StagedPaths = @(
    & git -c core.quotepath=false diff --cached --name-only --diff-filter=ACMR |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
)
foreach ($Path in $StagedPaths) {
    $Normalized = $Path.Replace("\", "/")
    $IsEnvironmentFile = (
        $Normalized -match "(^|/)\.env($|\.)" -and
        $Normalized -notmatch "\.example$"
    )
    $IsForbidden = (
        $IsEnvironmentFile -or
        $Normalized -match "(^|/)backend/data/secret_key$" -or
        $Normalized -match "(^|/)(venv|node_modules|__pycache__)(/|$)" -or
        $Normalized -match "(^|/)\.migration-backups(/|$)"
    )
    if ($IsForbidden) {
        throw "Refusing to publish sensitive or generated path: $Path"
    }

    $LocalPath = Join-Path $ProjectRoot $Path
    if (Test-Path -LiteralPath $LocalPath -PathType Leaf) {
        $Length = (Get-Item -LiteralPath $LocalPath).Length
        if ($Length -ge $MaximumGitFileBytes) {
            throw "File is too large for normal GitHub upload (>=95 MB): $Path"
        }
    }
}

$AllStagedPaths = @(
    & git -c core.quotepath=false diff --cached --name-only |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
)
if ($AllStagedPaths.Count -eq 0) {
    Write-Host "`nNo new changes to commit." -ForegroundColor Yellow
}
else {
    if ([string]::IsNullOrWhiteSpace($Message)) {
        $Message = Read-Host "Commit message"
    }
    if ([string]::IsNullOrWhiteSpace($Message)) {
        throw "A non-empty commit message is required"
    }

    Write-Host "`nFiles to publish:" -ForegroundColor Cyan
    $AllStagedPaths | ForEach-Object { Write-Host "  $_" }

    Invoke-Checked "Create Git commit" {
        git commit -m $Message
    }
}

if (-not $NoPush) {
    Invoke-Checked "Push origin/$Branch" {
        git push origin $Branch
    }
}

$Commit = (& git rev-parse HEAD).Trim()
Write-Host "`nGitHub release prepared successfully" -ForegroundColor Green
Write-Host "Branch: $Branch"
Write-Host "Commit: $Commit"
if ($NoPush) {
    Write-Host "Push: skipped (-NoPush)"
}
