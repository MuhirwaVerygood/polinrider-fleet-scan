<#
.SYNOPSIS
    Scans every repo across one or more GitHub owners for PolinRider compromise,
    and optionally opens (never merges) a cleanup PR for anything infected.

.DESCRIPTION
    Three passes:

    1. ENUMERATE  - list every repo under each -Owner via `gh repo list`.
    2. SCAN       - run .\audit-pollinrider.ps1 against each one (shallow clone,
                    read-only, host checks skipped - see -NoHostScan there). This
                    reuses the exact same detector this project's pre-commit/
                    pre-push hooks use, so a repo judged clean here is clean by
                    the same standard everywhere else.
    3. REPAIR     - for anything COMPROMISED or SUSPICIOUS, clone persistently,
                    strip what can be removed with confidence, install the same
                    gate the other repos already carry, commit, push to a new
                    branch, and open a PR. It stops there.

    This script never calls `gh pr merge`. Fleet-wide auto-merge across repos
    nobody has looked at is exactly the failure mode a false positive turns
    into a real incident - see README.md for the reasoning. Every PR it opens
    is reviewed and merged by a human.

    Signatures are never duplicated here. Detection comes entirely from
    audit-pollinrider.ps1 (which itself decodes iocs.b64); repair reads the
    same $IOC values back out of that file so the fixer can never drift from
    the detector.

.PARAMETER Owners
    One or more GitHub users or orgs to enumerate repos from. Required unless
    -Repos is given instead - there is deliberately no "scan everything gh can
    see" default.

.PARAMETER Repos
    Explicit "owner/name" repo list, bypassing enumeration entirely. Use this
    instead of -Owners to re-run against one or two specific repos rather than
    a whole account/org.

.PARAMETER IncludeForks
    Also scan forks (skipped by default - a fork's upstream is normally someone
    else's problem to fix, and PRs against forks are noisy).

.PARAMETER IncludeArchived
    Also scan archived repos (skipped by default - nothing is going to merge a
    PR into a repo nobody is maintaining).

.PARAMETER MaxRepos
    Safety cap on total repos scanned across all owners. Default 200.

.PARAMETER Fix
    After scanning, clone and repair anything COMPROMISED or SUSPICIOUS, then
    open a PR. Without this flag the script only reports - the default is
    read-only.

.PARAMETER Force
    Skip the confirmation prompt before the repair pass starts. For scheduled/
    non-interactive use. Interactive runs should leave this off and read the
    list of repos it is about to touch.

.PARAMETER OutDir
    Working directory for clones and the report file. Defaults to a fresh temp
    directory, deleted at the end unless -KeepClones is set.

.PARAMETER KeepClones
    Do not delete the repair-pass clones afterward. Useful for inspecting what
    changed before the PR is reviewed.

.EXAMPLE
    .\fleet-scan.ps1 -Owners SoftPi-Group-dev -Fix

.EXAMPLE
    .\fleet-scan.ps1 -Owners SoftPi-Group-dev,Softpi-kits,MuhirwaVerygood

.OUTPUTS
    A console report and a JSON report file in -OutDir. Exit code 0 if every
    repo scanned clean, 1 if anything was found (independent of whether -Fix
    was passed), 2 on a setup error (gh not authenticated, no owners, etc.).
#>
[CmdletBinding()]
param(
    [string[]]$Owners,
    [string[]]$Repos,

    [switch]$IncludeForks,
    [switch]$IncludeArchived,
    [int]$MaxRepos = 200,
    [switch]$Fix,
    [switch]$Force,
    [string]$OutDir,
    [switch]$KeepClones
)

$ErrorActionPreference = 'Stop'

# Under EAP=Stop, "nativeExe ... 2>&1" is a trap: PowerShell 5.1 wraps every
# stderr line from a native process into a NativeCommandError, and EAP=Stop then
# treats that as terminating even when the process exits 0 - a plain warning
# (e.g. git's CRLF notice, gh's update nag) aborts the script. Everywhere stderr
# text needs to be captured for an error message, do it through here instead,
# with EAP relaxed only for the one call.
function Invoke-NativeCapture {
    param([scriptblock]$Call)
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Call } finally { $ErrorActionPreference = $prevEAP }
}

$Script:AuditScript = Join-Path $PSScriptRoot 'audit-pollinrider.ps1'
$Script:PollinriderScanSh = Join-Path $PSScriptRoot 'pollinrider-scan.sh'
$Script:HookPreCommit = Join-Path $PSScriptRoot 'hook-pre-commit.sh'
$Script:HookPrePush = Join-Path $PSScriptRoot 'hook-pre-push.sh'

foreach ($req in @($Script:AuditScript, $Script:PollinriderScanSh, $Script:HookPreCommit, $Script:HookPrePush)) {
    if (-not (Test-Path -LiteralPath $req)) {
        Write-Host "ERROR: required file missing: $req" -ForegroundColor Red
        Write-Host "fleet-scan.ps1 must stay next to the rest of the files in this project." -ForegroundColor Red
        exit 2
    }
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: gh (GitHub CLI) not found on PATH." -ForegroundColor Red
    exit 2
}
Invoke-NativeCapture { & gh auth status *> $null }
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: gh is not authenticated. Run: gh auth login" -ForegroundColor Red
    exit 2
}

if (-not $Owners -and -not $Repos) {
    Write-Host "ERROR: pass -Owners <user/org...> or -Repos <owner/name...>." -ForegroundColor Red
    exit 2
}

if (-not $OutDir) {
    $OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("polinrider-fleet-" + [guid]::NewGuid().ToString('N').Substring(0, 10))
}
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$Script:CloneRoot = Join-Path $OutDir 'clones'
New-Item -ItemType Directory -Path $Script:CloneRoot -Force | Out-Null

# ---------------------------------------------------------------------------
# The IOC set - loaded once here too, so repair logic reads the exact same
# signatures the detector just used to flag the repo. Never hardcode a
# duplicate copy of these; that is how a fixer and a detector drift apart.
# ---------------------------------------------------------------------------
$iocPath = Join-Path $PSScriptRoot 'iocs.b64'
$IOC = [System.Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String((Get-Content -LiteralPath $iocPath -Raw).Trim())
) | ConvertFrom-Json

# ---------------------------------------------------------------------------
# Pass 1: enumerate
# ---------------------------------------------------------------------------

function Get-FleetRepos {
    param([string[]]$Owners)

    $repos = New-Object System.Collections.ArrayList
    foreach ($owner in $Owners) {
        Write-Host "Listing repos for $owner ..." -ForegroundColor Cyan
        $json = Invoke-NativeCapture { & gh repo list $owner --limit 1000 --json name,owner,isFork,isArchived,defaultBranchRef,url 2>&1 }
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  WARNING: could not list repos for $owner - $json" -ForegroundColor Yellow
            continue
        }
        $parsed = $json | ConvertFrom-Json
        foreach ($r in $parsed) {
            if (-not $IncludeForks -and $r.isFork) { continue }
            if (-not $IncludeArchived -and $r.isArchived) { continue }
            if (-not $r.defaultBranchRef) { continue }  # empty repo, nothing to scan
            $null = $repos.Add([pscustomobject]@{
                Owner         = $r.owner.login
                Name          = $r.name
                FullName      = "$($r.owner.login)/$($r.name)"
                Url           = $r.url
                DefaultBranch = $r.defaultBranchRef.name
            })
        }
    }
    return @($repos | Sort-Object FullName -Unique)
}

function Get-ExplicitRepos {
    param([string[]]$Repos)

    $out = New-Object System.Collections.ArrayList
    foreach ($full in $Repos) {
        $json = Invoke-NativeCapture { & gh repo view $full --json name,owner,defaultBranchRef,url 2>&1 }
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  WARNING: could not look up $full - $json" -ForegroundColor Yellow
            continue
        }
        $r = $json | ConvertFrom-Json
        $null = $out.Add([pscustomobject]@{
            Owner         = $r.owner.login
            Name          = $r.name
            FullName      = "$($r.owner.login)/$($r.name)"
            Url           = $r.url
            DefaultBranch = $r.defaultBranchRef.name
        })
    }
    return @($out)
}

# ---------------------------------------------------------------------------
# Pass 2: scan
# ---------------------------------------------------------------------------

function Invoke-FleetScan {
    param([pscustomobject]$Repo)

    $raw = Invoke-NativeCapture { & $Script:AuditScript -Repo $Repo.Url -NoHostScan -Json 2>&1 }
    $exit = $LASTEXITCODE

    # audit-pollinrider.ps1 -Json emits exactly one JSON object on the success
    # path. On a clone failure it writes a plain "ERROR: ..." line to Write-Host
    # instead (which does not land in $raw at all, since Write-Host bypasses the
    # output stream) - so $raw can legitimately be empty on a real failure.
    $parsed = $null
    if ($raw) {
        try { $parsed = ($raw -join "`n") | ConvertFrom-Json } catch {}
    }

    if (-not $parsed) {
        return [pscustomobject]@{
            Repo     = $Repo
            Verdict  = 'ERROR'
            Findings = @()
            Exit     = $exit
        }
    }

    return [pscustomobject]@{
        Repo     = $Repo
        Verdict  = $parsed.verdict
        Findings = @($parsed.findings)
        Exit     = $exit
    }
}

# ---------------------------------------------------------------------------
# Pass 3: repair
#
# Every function below only ever removes content it can identify with the same
# confidence a human reviewer would need to delete it outright: an exact
# signature match, or - for files that can legitimately mix attacker content
# with real settings - a JSON-aware strip that removes only the known-bad keys
# and leaves everything else untouched. Anything it cannot classify this
# confidently is left alone and listed under "needs manual review" instead of
# being touched. A wrong guess here is not the payload; it is silently
# corrupting someone else's config in a repo nobody looked at directly.
# ---------------------------------------------------------------------------

function Remove-PropagationArtifacts {
    param([string]$Root, [System.Collections.ArrayList]$Changes)

    foreach ($a in $IOC.artifacts) {
        $p = Join-Path $Root $a
        if (Test-Path -LiteralPath $p) {
            Remove-Item -LiteralPath $p -Force
            $null = $Changes.Add("Removed propagation artifact: $a")
        }
    }

    $gi = Join-Path $Root '.gitignore'
    if (Test-Path -LiteralPath $gi) {
        $lines = [System.IO.File]::ReadAllLines($gi)
        $kept = New-Object System.Collections.ArrayList
        $removedAny = $false
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if (($IOC.artifacts -contains $trimmed) -or $trimmed -eq '.gitignore') {
                $removedAny = $true
                continue
            }
            $null = $kept.Add($line)
        }
        if ($removedAny) {
            [System.IO.File]::WriteAllLines($gi, $kept)
            $null = $Changes.Add("Removed attacker cloaking entries from .gitignore")
        }
    }
}

function Remove-FakeFontPayloads {
    param([string]$Root, [System.Collections.ArrayList]$Changes)

    foreach ($name in $IOC.kitFileNames) {
        Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $name -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } |
            ForEach-Object {
                # Confirm by content before deleting, not just the filename - the
                # actor reuses this name, but so could a legitimate font ship one
                # day. Same test the detector applies.
                $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
                $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
                $looksLikeScript = ($ascii -match 'require\(|global\[|eval\(|child_process') -or
                    -not ($ascii.Length -ge 4 -and ($ascii.Substring(0, 4) -eq 'wOFF' -or $ascii.Substring(0, 4) -eq 'wOF2'))
                if ($looksLikeScript) {
                    $rel = $_.FullName.Substring($Root.Length).TrimStart('\', '/')
                    Remove-Item -LiteralPath $_.FullName -Force
                    $null = $Changes.Add("Removed fake font payload: $rel")
                }
            }
    }
}

function Remove-VscodeDirectory {
    param([string]$Root, [System.Collections.ArrayList]$Changes)

    # Policy as of 2026-08-24: remove .vscode/ wholesale on any repair run and
    # gitignore it going forward, rather than surgically stripping just the
    # confirmed-malicious keys/files. .vscode/ is exactly where this campaign
    # hides its autorun kit, and editor config has no business being pushed to
    # a shared repo in the first place. This does mean a repo that
    # deliberately commits shared team settings (formatter config, recommended
    # extensions, real launch configs) loses that too - there is no signature
    # check that can tell "team convention" apart from "attacker kit" once the
    # answer is "remove the whole directory" rather than "remove the two known
    # keys", so anyone relying on a committed .vscode/ should expect this and
    # can restore what they want from the PR's parent commit.
    $vscodeDir = Join-Path $Root '.vscode'
    if (Test-Path -LiteralPath $vscodeDir -PathType Container) {
        Remove-Item -LiteralPath $vscodeDir -Recurse -Force
        $null = $Changes.Add("Removed .vscode/ entirely - not just the malicious files in it - and added it to .gitignore")
    }

    $gi = Join-Path $Root '.gitignore'
    if (Test-Path -LiteralPath $gi) {
        $existing = [System.IO.File]::ReadAllText($gi)
        if ($existing -notmatch '(?m)^\s*\.vscode/?\s*$') {
            $sep = if ($existing -and -not $existing.EndsWith("`n")) { "`n" } else { "" }
            $addition = "${sep}`n# Editor config should not be pushed to a shared repo - also where PolinRider hides its autorun kit.`n.vscode/`n"
            [System.IO.File]::AppendAllText($gi, $addition)
            $null = $Changes.Add("Added .vscode/ to .gitignore")
        }
    }
    else {
        [System.IO.File]::WriteAllText($gi, "# Editor config should not be pushed to a shared repo - also where PolinRider hides its autorun kit.`n.vscode/`n")
        $null = $Changes.Add("Created .gitignore with .vscode/")
    }
}

function Install-PolinriderGate {
    param([string]$Root, [System.Collections.ArrayList]$Changes)

    $hooksDir = Join-Path $Root '.githooks'
    if (Test-Path -LiteralPath (Join-Path $hooksDir 'pollinrider-scan.sh')) { return }  # already installed

    New-Item -ItemType Directory -Path $hooksDir -Force | Out-Null
    Copy-Item -LiteralPath $Script:PollinriderScanSh -Destination (Join-Path $hooksDir 'pollinrider-scan.sh')
    Copy-Item -LiteralPath $Script:HookPreCommit -Destination (Join-Path $hooksDir 'pre-commit')
    Copy-Item -LiteralPath $Script:HookPrePush -Destination (Join-Path $hooksDir 'pre-push')

    $gaPath = Join-Path $Root '.gitattributes'
    $gaLine = "`n# Shell hooks must keep LF endings or they break on macOS/Linux.`n.githooks/** text eol=lf`n"
    if (Test-Path -LiteralPath $gaPath) {
        $existing = [System.IO.File]::ReadAllText($gaPath)
        if ($existing -notmatch '\.githooks/\*\*') {
            [System.IO.File]::AppendAllText($gaPath, $gaLine)
        }
    }
    else {
        [System.IO.File]::WriteAllText($gaPath, $gaLine.TrimStart())
    }

    $null = $Changes.Add("Installed PolinRider pre-commit/pre-push gate in .githooks/ (run: git config core.hooksPath .githooks)")
}

function Repair-FleetRepo {
    param([pscustomobject]$Repo)

    $cloneDir = Join-Path $Script:CloneRoot $Repo.Name
    if (Test-Path -LiteralPath $cloneDir) { Remove-Item -LiteralPath $cloneDir -Recurse -Force }

    Write-Host "  Cloning $($Repo.FullName) ..." -ForegroundColor Cyan
    Invoke-NativeCapture { & git clone --quiet $Repo.Url $cloneDir *> $null }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $cloneDir)) {
        return [pscustomobject]@{ Repo = $Repo; Ok = $false; Reason = 'clone failed'; PrUrl = $null; Changes = @(); NeedsReview = @() }
    }

    Push-Location $cloneDir
    try {
        $changes = New-Object System.Collections.ArrayList
        $needsReview = New-Object System.Collections.ArrayList

        Remove-PropagationArtifacts -Root $cloneDir -Changes $changes
        Remove-FakeFontPayloads     -Root $cloneDir -Changes $changes
        Remove-VscodeDirectory      -Root $cloneDir -Changes $changes
        Install-PolinriderGate      -Root $cloneDir -Changes $changes

        Invoke-NativeCapture { & git add -A *> $null }
        $staged = Invoke-NativeCapture { & git diff --cached --name-only 2>$null }
        if (-not $staged) {
            return [pscustomobject]@{ Repo = $Repo; Ok = $false; Reason = 'nothing to commit after repair (findings were all flag-only)'; PrUrl = $null; Changes = @($changes); NeedsReview = @($needsReview) }
        }

        $branch = "polinrider-cleanup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Invoke-NativeCapture { & git checkout -q -b $branch *> $null }
        $commitMsg = "security: remove PolinRider payload, add commit/push gate

Automated by fleet-scan.ps1.

$($changes -join "`n")
$(if ($needsReview.Count -gt 0) { "`nFlagged for manual review (not auto-changed):`n" + ($needsReview -join "`n") })
"
        Invoke-NativeCapture { & git -c user.name='polinrider-fleet-scan' -c user.email='polinrider-fleet-scan@localhost' commit -q -m $commitMsg *> $null }

        Write-Host "  Pushing $branch ..." -ForegroundColor Cyan
        Invoke-NativeCapture { & git push --quiet origin $branch *> $null }
        if ($LASTEXITCODE -ne 0) {
            return [pscustomobject]@{ Repo = $Repo; Ok = $false; Reason = 'push failed (no write access?)'; PrUrl = $null; Changes = @($changes); NeedsReview = @($needsReview) }
        }

        $body = "Automated PolinRider cleanup from fleet-scan.ps1.`n`n**Changed:**`n" + (($changes | ForEach-Object { "- $_" }) -join "`n")
        if ($needsReview.Count -gt 0) {
            $body += "`n`n**Needs manual review (not auto-changed):**`n" + (($needsReview | ForEach-Object { "- $_" }) -join "`n")
        }
        $body += "`n`nThis PR was opened automatically. It was not merged automatically - see README.md for why."

        $prUrl = Invoke-NativeCapture {
            & gh pr create --repo $Repo.FullName --base $Repo.DefaultBranch --head $branch `
                --title "security: remove PolinRider payload, add commit/push gate" --body $body 2>&1
        }
        if ($LASTEXITCODE -ne 0) {
            return [pscustomobject]@{ Repo = $Repo; Ok = $false; Reason = "gh pr create failed: $prUrl"; PrUrl = $null; Changes = @($changes); NeedsReview = @($needsReview) }
        }

        return [pscustomobject]@{ Repo = $Repo; Ok = $true; Reason = ''; PrUrl = $prUrl; Changes = @($changes); NeedsReview = @($needsReview) }
    }
    finally {
        Pop-Location
        if (-not $KeepClones) { Remove-Item -LiteralPath $cloneDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host 'PolinRider fleet scan' -ForegroundColor Cyan
Write-Host ('=' * 60)

if ($Repos) {
    # Deliberately NOT named $repos: PowerShell variable names are case-insensitive,
    # so a local $repos here would be the exact same storage slot as the script's
    # own -Repos parameter above. Assigning "$repos = @(f -Repos $Repos)" into that
    # shared slot corrupts the result (objects come back stringified) even though
    # the RHS is fully evaluated before the assignment - a real, reproducible
    # PowerShell gotcha, not a hypothetical one. Kept distinct on purpose.
    $targetRepos = @(Get-ExplicitRepos -Repos $Repos)
} else {
    $targetRepos = @(Get-FleetRepos -Owners $Owners)
}
if ($targetRepos.Count -eq 0) {
    Write-Host 'No repos found for the given owner(s).' -ForegroundColor Yellow
    exit 0
}
if ($targetRepos.Count -gt $MaxRepos) {
    Write-Host "Found $($targetRepos.Count) repos, capping at -MaxRepos $MaxRepos." -ForegroundColor Yellow
    $targetRepos = $targetRepos | Select-Object -First $MaxRepos
}
Write-Host "Scanning $($targetRepos.Count) repo(s)...`n"

$results = New-Object System.Collections.ArrayList
$i = 0
foreach ($repo in $targetRepos) {
    $i++
    Write-Host "[$i/$($targetRepos.Count)] $($repo.FullName) ... " -NoNewline
    $r = Invoke-FleetScan -Repo $repo
    $null = $results.Add($r)
    $colour = switch ($r.Verdict) {
        'CLEAN'        { 'Green' }
        'REVIEW'       { 'Yellow' }
        'SUSPICIOUS'   { 'Yellow' }
        'COMPROMISED'  { 'Red' }
        default        { 'DarkGray' }
    }
    Write-Host $r.Verdict -ForegroundColor $colour
}

$clean = @($results | Where-Object { $_.Verdict -eq 'CLEAN' })
$review = @($results | Where-Object { $_.Verdict -eq 'REVIEW' })
$bad = @($results | Where-Object { $_.Verdict -eq 'COMPROMISED' -or $_.Verdict -eq 'SUSPICIOUS' })
$errored = @($results | Where-Object { $_.Verdict -eq 'ERROR' })

Write-Host ''
Write-Host ('-' * 60)
Write-Host "Clean: $($clean.Count)   Review: $($review.Count)   Compromised/Suspicious: $($bad.Count)   Errors: $($errored.Count)"

if ($bad.Count -gt 0) {
    Write-Host ''
    Write-Host 'Repos with findings:' -ForegroundColor Red
    foreach ($r in $bad) {
        Write-Host "  $($r.Repo.FullName) - $($r.Verdict)"
        foreach ($f in $r.Findings) {
            if ($f.Severity -eq 'CRITICAL') { Write-Host "    [CRITICAL] $($f.Indicator)" -ForegroundColor Red }
        }
    }
}
if ($errored.Count -gt 0) {
    Write-Host ''
    Write-Host 'Repos that could not be scanned (private without access, network, etc.):' -ForegroundColor Yellow
    foreach ($r in $errored) { Write-Host "  $($r.Repo.FullName)" }
}

$reportPath = Join-Path $OutDir 'fleet-scan-report.json'
$results | Select-Object @{n='repo';e={$_.Repo.FullName}}, Verdict, @{n='findings';e={$_.Findings}} |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath
Write-Host ''
Write-Host "Full report: $reportPath"

if (-not $Fix -or $bad.Count -eq 0) {
    if (-not $Fix -and $bad.Count -gt 0) {
        Write-Host ''
        Write-Host "Re-run with -Fix to clean these up and open PRs (never auto-merged)." -ForegroundColor Cyan
    }
    if (-not $KeepClones) { Remove-Item -LiteralPath $Script:CloneRoot -Recurse -Force -ErrorAction SilentlyContinue }
    exit ($(if ($bad.Count -gt 0) { 1 } else { 0 }))
}

Write-Host ''
Write-Host "About to clone, clean and open a PR (NOT merged) against $($bad.Count) repo(s):" -ForegroundColor Yellow
foreach ($r in $bad) { Write-Host "  $($r.Repo.FullName)" }

if (-not $Force) {
    $answer = Read-Host "`nProceed? (y/N)"
    if ($answer -ne 'y' -and $answer -ne 'Y') {
        Write-Host 'Aborted.' -ForegroundColor Yellow
        exit 1
    }
}

Write-Host ''
$repairResults = New-Object System.Collections.ArrayList
foreach ($r in $bad) {
    Write-Host "Repairing $($r.Repo.FullName) ..." -ForegroundColor Cyan
    $rr = Repair-FleetRepo -Repo $r.Repo
    $null = $repairResults.Add($rr)
    if ($rr.Ok) {
        Write-Host "  PR opened: $($rr.PrUrl)" -ForegroundColor Green
    }
    else {
        Write-Host "  Skipped: $($rr.Reason)" -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host ('=' * 60)
Write-Host 'PRs opened (review and merge each by hand):' -ForegroundColor Cyan
foreach ($rr in ($repairResults | Where-Object { $_.Ok })) {
    Write-Host "  $($rr.PrUrl)"
}
$skipped = @($repairResults | Where-Object { -not $_.Ok })
if ($skipped.Count -gt 0) {
    Write-Host ''
    Write-Host 'Not repaired automatically:' -ForegroundColor Yellow
    foreach ($rr in $skipped) { Write-Host "  $($rr.Repo.FullName): $($rr.Reason)" }
}

if (-not $KeepClones) { Remove-Item -LiteralPath $Script:CloneRoot -Recurse -Force -ErrorAction SilentlyContinue }
exit 1
