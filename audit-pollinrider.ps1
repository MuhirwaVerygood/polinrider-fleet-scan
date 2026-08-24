<#
.SYNOPSIS
    Audits a git repository for evidence of PolinRider (DPRK) supply-chain compromise.

.DESCRIPTION
    Give it a repo URL. It shallow-clones to a temp directory, scans for the
    published PolinRider indicators, prints the evidence it found, and deletes
    the clone. A local path works too, and is scanned in place.

    Two deliberate design choices:

    1. No Node dependency. The campaign's payloads execute under Node, so on a
       suspect host the Node toolchain is exactly what you cannot trust to audit
       itself. Nothing scanned is ever executed.

    2. Signatures live base64-encoded in iocs.b64, not as literals in this file.
       A detector carrying plaintext malware signatures trips AMSI and on-access
       AV, which blocks the detector from running at all.

.PARAMETER Repo
    Repo URL (https / ssh / "owner/name" shorthand) or a local directory path.

.PARAMETER Deep
    Clone full history instead of --depth 1. Enables the commit-history checks.

.PARAMETER IncludeNodeModules
    Also scan node_modules (skipped by default; only relevant for local paths).

.PARAMETER Json
    Emit findings as JSON instead of a table.

.PARAMETER ShowIocs
    Print the decoded indicator set and exit. No scanning.

.PARAMETER NoHostScan
    Skip the host checks (npm's own install, live node processes). On by
    default: the payload has been found appended directly to npm's own
    lib/cli.js - meaning every npm/npx call on the machine re-runs it - and
    confirmed running as a live process with an open C2 connection. Neither
    shows up in a file scan of the repo, which is why they run separately.

.EXAMPLE
    .\audit-pollinrider.ps1 https://github.com/owner/repo
    .\audit-pollinrider.ps1 owner/repo -Deep
    .\audit-pollinrider.ps1 C:\code\my-project

.OUTPUTS
    Exit code 0 = clean, 1 = compromised/suspicious, 2 = error.

.NOTES
    See README.md for IOC provenance and per-indicator citations.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Repo,

    [switch]$Deep,
    [switch]$IncludeNodeModules,
    [switch]$Json,
    [switch]$ShowIocs,
    [switch]$NoHostScan
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Indicator set
# ---------------------------------------------------------------------------

$iocPath = Join-Path $PSScriptRoot 'iocs.b64'
if (-not (Test-Path -LiteralPath $iocPath)) {
    Write-Host "ERROR: indicator file not found: $iocPath" -ForegroundColor Red
    exit 2
}

try {
    $raw = [System.Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String((Get-Content -LiteralPath $iocPath -Raw).Trim())
    )
    $IOC = $raw | ConvertFrom-Json
}
catch {
    Write-Host "ERROR: could not decode $iocPath - $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

if ($ShowIocs) {
    Write-Host "PolinRider indicator set - version $($IOC.version)" -ForegroundColor Cyan
    Write-Host "Source: $($IOC.source)"
    Write-Host ''
    $raw
    exit 0
}

if (-not $Repo) {
    Write-Host 'ERROR: supply a repo URL or local path. See -? for help.' -ForegroundColor Red
    exit 2
}

$Script:TextExtensions = @(
    '.js', '.cjs', '.mjs', '.ts', '.tsx', '.jsx', '.json',
    '.bat', '.cmd', '.sh', '.ps1', '.yml', '.yaml', '.md'
)

$Script:Findings = New-Object System.Collections.ArrayList
$Script:MaxFileBytes = 8MB

# Generated output. Scanning it produces noise, and a payload there is a copy of
# one already in source, so it never adds a finding you would act on separately.
# quarantine holds forensic evidence and raw malware samples on purpose - scanning
# it does not tell you anything about whether the repo itself is compromised, it
# just re-reports what was already deliberately captured.
$Script:ExcludedDirs = @('.git', '.next', 'dist', 'build', 'out', 'coverage', '.turbo', '.svelte-kit', 'quarantine')

function Test-ExcludedPath {
    param([string]$FullName)

    foreach ($d in $Script:ExcludedDirs) {
        if ($FullName -match ([regex]::Escape("\$d\")) -or $FullName -match ([regex]::Escape("/$d/"))) {
            return $true
        }
    }
    if (-not $IncludeNodeModules -and $FullName -match '[\\/]node_modules[\\/]') { return $true }
    return $false
}

function Add-Finding {
    param(
        [ValidateSet('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')][string]$Severity,
        [string]$Category,
        [string]$File,
        [int]$Line,
        [string]$Indicator,
        [string]$Evidence
    )
    $null = $Script:Findings.Add([pscustomobject]@{
        Severity  = $Severity
        Category  = $Category
        File      = $File
        Line      = $Line
        Indicator = $Indicator
        Evidence  = $Evidence
    })
}

# Neutralise anything echoed back: no live URLs, no runnable payload fragments.
function Format-Evidence {
    param([string]$Text, [int]$Max = 110)
    if (-not $Text) { return '' }
    $clean = ($Text -replace '\s+', ' ').Trim()
    if ($clean.Length -gt $Max) { $clean = $clean.Substring(0, $Max) + '...' }
    return ($clean -replace 'http', 'hxxp')
}

function Get-LineNumber {
    param([string]$Content, [int]$Index)
    if ($Index -lt 1) { return 1 }
    return ([regex]::Matches($Content.Substring(0, $Index), "`n")).Count + 1
}

function Find-Literal {
    param([string]$Content, [string]$Needle)
    return $Content.IndexOf($Needle, [System.StringComparison]::Ordinal)
}

function Get-Snippet {
    param([string]$Content, [int]$Index, [int]$Length = 70)
    $take = [Math]::Min($Length, $Content.Length - $Index)
    if ($take -le 0) { return '' }
    return (Format-Evidence $Content.Substring($Index, $take))
}

# ---------------------------------------------------------------------------
# Detection passes
# ---------------------------------------------------------------------------

# Mirrors the official polinrider_payload YARA rule, plus one extra rule: an
# injection marker together with the require/module loader globals is treated as
# conclusive even when no shuffle seed survives in the file. Real samples exist
# where the seeds are absent but the injection marker and loader pair are not.
function Test-PayloadSignatures {
    param([string]$Content, [string]$Rel)

    $hits = @{}
    $probes = @(
        @{ K = 'MarkerV1';  V = $IOC.markerV1 },
        @{ K = 'MarkerV2';  V = $IOC.markerV2 },
        @{ K = 'GlobalV1';  V = $IOC.globalV1 },
        @{ K = 'GlobalV2';  V = $IOC.globalV2 },
        @{ K = 'DecoderV1'; V = $IOC.decoderV1 },
        @{ K = 'DecoderV2'; V = $IOC.decoderV2 },
        @{ K = 'GlobalReq'; V = $IOC.globalReq },
        @{ K = 'GlobalMod'; V = $IOC.globalMod }
    )
    foreach ($p in $probes) {
        $idx = Find-Literal -Content $Content -Needle $p.V
        if ($idx -ge 0) { $hits[$p.K] = $idx }
    }

    $seedV1 = $null
    foreach ($s in $IOC.seedsV1) {
        $i = Find-Literal -Content $Content -Needle $s
        if ($i -ge 0) { $seedV1 = @{ Seed = $s; Index = $i }; break }
    }
    $seedV2 = $null
    foreach ($s in $IOC.seedsV2) {
        $i = Find-Literal -Content $Content -Needle $s
        if ($i -ge 0) { $seedV2 = @{ Seed = $s; Index = $i }; break }
    }

    # Tier 1: unique signature marker. Conclusive on its own.
    if ($hits.ContainsKey('MarkerV1')) {
        Add-Finding -Severity 'CRITICAL' -Category 'Payload' -File $Rel `
            -Line (Get-LineNumber $Content $hits['MarkerV1']) `
            -Indicator 'Signature marker, original variant (v1)' `
            -Evidence (Get-Snippet $Content $hits['MarkerV1'])
    }
    if ($hits.ContainsKey('MarkerV2')) {
        Add-Finding -Severity 'CRITICAL' -Category 'Payload' -File $Rel `
            -Line (Get-LineNumber $Content $hits['MarkerV2']) `
            -Indicator 'Signature marker, rotated variant (v2)' `
            -Evidence (Get-Snippet $Content $hits['MarkerV2'])
    }

    # Tier 1: injection marker paired with its own variant's seed or decoder.
    if ($hits.ContainsKey('GlobalV1') -and ($seedV1 -or $hits.ContainsKey('DecoderV1'))) {
        Add-Finding -Severity 'CRITICAL' -Category 'Payload' -File $Rel `
            -Line (Get-LineNumber $Content $hits['GlobalV1']) `
            -Indicator 'v1 injection marker with matching seed/decoder' `
            -Evidence 'Original variant obfuscator confirmed'
    }
    if ($hits.ContainsKey('GlobalV2') -and ($seedV2 -or $hits.ContainsKey('DecoderV2'))) {
        Add-Finding -Severity 'CRITICAL' -Category 'Payload' -File $Rel `
            -Line (Get-LineNumber $Content $hits['GlobalV2']) `
            -Indicator 'v2 injection marker with matching seed/decoder' `
            -Evidence 'Rotated variant obfuscator confirmed'
    }

    # Tier 1 extension: injection marker plus both loader globals, seeds absent.
    $hasLoaderGlobals = $hits.ContainsKey('GlobalReq') -and $hits.ContainsKey('GlobalMod')
    $injKey = $null
    if ($hits.ContainsKey('GlobalV1')) { $injKey = 'GlobalV1' }
    elseif ($hits.ContainsKey('GlobalV2')) { $injKey = 'GlobalV2' }

    if ($injKey -and $hasLoaderGlobals) {
        $variant = 'v1'
        if ($injKey -eq 'GlobalV2') { $variant = 'v2' }
        Add-Finding -Severity 'CRITICAL' -Category 'Payload' -File $Rel `
            -Line (Get-LineNumber $Content $hits[$injKey]) `
            -Indicator "$variant injection marker with require/module loader pair" `
            -Evidence (Get-Snippet $Content $hits[$injKey] 80)
    }

    # Tier 2: loader globals plus any shuffle seed, no injection marker.
    if ($hasLoaderGlobals -and -not $injKey) {
        $sd = $seedV1
        if (-not $sd) { $sd = $seedV2 }
        if ($sd) {
            Add-Finding -Severity 'HIGH' -Category 'Payload' -File $Rel `
                -Line (Get-LineNumber $Content $sd.Index) `
                -Indicator 'Loader globals with known shuffle seed' `
                -Evidence 'Shuffle-cipher obfuscator structure'
        }
    }

    # Re-injection primitive documented in the dossier.
    $spawnIdx = Find-Literal -Content $Content -Needle $IOC.spawnStub
    if ($spawnIdx -ge 0 -and $injKey) {
        Add-Finding -Severity 'CRITICAL' -Category 'Payload' -File $Rel `
            -Line (Get-LineNumber $Content $spawnIdx) `
            -Indicator 'child_process spawn re-injection stub' `
            -Evidence 'Payload respawns itself in a child node process'
    }
}

# Payload is appended after the real config, preceded by a long whitespace run so
# it sits off-screen. Signature-independent, so it survives constant rotation.
function Test-StructuralAnomaly {
    param([string]$Content, [string]$Rel, [long]$Bytes, [bool]$IsConfig)

    # The padding check applies to EVERY file, not just named configs. The same
    # payload has been found appended to npm's own lib/cli.js and hidden inside a
    # .woff2, so restricting this to a filename list misses real infections.
    # Minified bundles contain no 80-character whitespace runs, so long lines on
    # their own do not trigger it.
    $lineNo = 0
    foreach ($ln in ($Content -split "`n")) {
        $lineNo++
        if ($ln.Length -lt 400) { continue }

        $pad = [regex]::Match($ln, '\s{80,}')
        if ($pad.Success -and ($pad.Index + $pad.Length) -lt ($ln.Length - 200)) {
            $tail = $ln.Length - $pad.Index - $pad.Length
            Add-Finding -Severity 'CRITICAL' -Category 'Structure' -File $Rel -Line $lineNo `
                -Indicator "Hidden appended payload: $($pad.Length) whitespace chars then $tail chars of code" `
                -Evidence 'Content pushed off the right margin so it is invisible in an editor'
            return
        }
        if ($IsConfig) {
            Add-Finding -Severity 'MEDIUM' -Category 'Structure' -File $Rel -Line $lineNo `
                -Indicator "Abnormally long line in config file ($($ln.Length) chars)" `
                -Evidence 'Build configs are not normally minified'
            return
        }
    }

    if (-not $IsConfig) { return }

    if ($Bytes -gt 4096) {
        Add-Finding -Severity 'MEDIUM' -Category 'Structure' -File $Rel -Line 1 `
            -Indicator "Oversized config file ($Bytes bytes)" `
            -Evidence 'Legitimate build configs are typically well under 1 KB'
    }
}

# Glassworm sibling loader hides source in Unicode variation selectors.
function Test-InvisibleUnicode {
    param([string]$Content, [string]$Rel)

    $m = [regex]::Match($Content, '[\uFE00-\uFE0F]{8,}')
    if (-not $m.Success) { $m = [regex]::Match($Content, '\uDB40[\uDD00-\uDDEF]{4,}') }
    if ($m.Success) {
        Add-Finding -Severity 'HIGH' -Category 'Payload' -File $Rel `
            -Line (Get-LineNumber $Content $m.Index) `
            -Indicator 'Unicode variation-selector encoded payload (Glassworm decoder)' `
            -Evidence 'Invisible characters carrying encoded source'
    }
}

function Test-NetworkIocs {
    param([string]$Content, [string]$Rel)

    foreach ($h in $IOC.c2Hosts) {
        $i = Find-Literal -Content $Content -Needle $h
        if ($i -ge 0) {
            Add-Finding -Severity 'CRITICAL' -Category 'C2' -File $Rel `
                -Line (Get-LineNumber $Content $i) `
                -Indicator "Known C2 bootstrap host referenced" `
                -Evidence (Get-Snippet $Content $i 90)
        }
    }
    foreach ($ip in $IOC.c2Ips) {
        $i = Find-Literal -Content $Content -Needle $ip
        if ($i -ge 0) {
            Add-Finding -Severity 'CRITICAL' -Category 'C2' -File $Rel `
                -Line (Get-LineNumber $Content $i) `
                -Indicator "Known payload-staging IP referenced" -Evidence $ip
        }
    }
    foreach ($d in $IOC.deadDrops) {
        $i = Find-Literal -Content $Content -Needle $d
        if ($i -ge 0) {
            Add-Finding -Severity 'CRITICAL' -Category 'C2' -File $Rel `
                -Line (Get-LineNumber $Content $i) `
                -Indicator 'Blockchain dead-drop address' -Evidence $d
        }
    }
    if ($IOC.xorKeys) {
        foreach ($k in $IOC.xorKeys) {
            $i = Find-Literal -Content $Content -Needle $k
            if ($i -ge 0) {
                Add-Finding -Severity 'CRITICAL' -Category 'C2' -File $Rel `
                    -Line (Get-LineNumber $Content $i) `
                    -Indicator 'PolinRider stage-2 XOR decode key' -Evidence ''
            }
        }
    }

    $u = Find-Literal -Content $Content -Needle $IOC.stakingUuid
    if ($u -ge 0) {
        Add-Finding -Severity 'CRITICAL' -Category 'Lure' -File $Rel `
            -Line (Get-LineNumber $Content $u) `
            -Indicator 'Weaponized take-home template UUID' -Evidence $IOC.stakingUuid
    }
}

function Test-TasksJson {
    param([string]$Root)

    $p = Join-Path $Root '.vscode/tasks.json'
    if (-not (Test-Path -LiteralPath $p)) { return }

    $c = [System.IO.File]::ReadAllText($p)
    if ($c -notmatch 'folderOpen') { return }

    $sev = 'MEDIUM'
    $note = 'Task auto-runs when the folder is opened'

    if ($c -match 'curl|wget|Invoke-WebRequest|bash -c|powershell -') {
        $sev = 'CRITICAL'
        $note = 'Auto-run task fetches and executes remote content'
    }

    # An interpreter pointed at a non-code asset is the fake-font execution vector:
    # the payload hides under a font/image extension so the task line looks benign.
    $assetExec = [regex]::Match($c, '(node|deno|bun|python3?|py)\s+[^\s"|&;]*\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico|dat|bin|svg)\b')
    if ($assetExec.Success) {
        $sev = 'CRITICAL'
        $note = "Auto-run task executes a non-code asset: $($assetExec.Value)"
    }

    Add-Finding -Severity $sev -Category 'TasksJacker' -File '.vscode/tasks.json' -Line 1 `
        -Indicator 'Task configured to run on folder open' -Evidence $note

    # Silencing flags are what make the above invisible in normal use.
    if ($c -match '"hide"\s*:\s*true' -and $c -match '"reveal"\s*:\s*"never"') {
        Add-Finding -Severity 'HIGH' -Category 'TasksJacker' -File '.vscode/tasks.json' -Line 1 `
            -Indicator 'Auto-run task hidden from the task list and terminal' `
            -Evidence 'hide:true with presentation.reveal:never'
    }
}

# The folderOpen task only fires without a prompt when the workspace opts in.
function Test-VsCodeSettings {
    param([string]$Root)

    $p = Join-Path $Root '.vscode/settings.json'
    if (-not (Test-Path -LiteralPath $p)) { return }

    $c = [System.IO.File]::ReadAllText($p)

    if ($c -match '"task\.allowAutomaticTasks"\s*:\s*true') {
        Add-Finding -Severity 'HIGH' -Category 'TasksJacker' -File '.vscode/settings.json' -Line 1 `
            -Indicator 'task.allowAutomaticTasks enabled' `
            -Evidence 'Removes the confirmation prompt before folderOpen tasks run'
    }
    if ($c -match '"terminal\.integrated\.hideOnStartup"\s*:\s*"always"') {
        Add-Finding -Severity 'MEDIUM' -Category 'TasksJacker' -File '.vscode/settings.json' -Line 1 `
            -Indicator 'Integrated terminal hidden on startup' `
            -Evidence 'Conceals output of any task that runs at folder open'
    }
}

function Test-Artifacts {
    param([string]$Root)

    foreach ($a in $IOC.artifacts) {
        if (Test-Path -LiteralPath (Join-Path $Root $a)) {
            Add-Finding -Severity 'CRITICAL' -Category 'Propagation' -File $a -Line 0 `
                -Indicator "Propagation artifact present: $a" `
                -Evidence 'Direct evidence of compromise even if the payload was cleaned'
        }
    }

    $gi = Join-Path $Root '.gitignore'
    if (-not (Test-Path -LiteralPath $gi)) { return }

    $lines = [System.IO.File]::ReadAllLines($gi)
    for ($n = 0; $n -lt $lines.Count; $n++) {
        if ($IOC.artifacts -contains $lines[$n].Trim()) {
            Add-Finding -Severity 'HIGH' -Category 'Propagation' -File '.gitignore' -Line ($n + 1) `
                -Indicator "Orchestrator filename injected into .gitignore: $($lines[$n].Trim())" `
                -Evidence 'Hides the malware orchestrator from git status'
        }
    }
}

function Test-Dependencies {
    param([string]$Root)

    $pkgs = Get-ChildItem -LiteralPath $Root -Filter 'package.json' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { -not (Test-ExcludedPath $_.FullName) -and $_.FullName -notmatch '[\\/]node_modules[\\/]' }

    foreach ($pkg in $pkgs) {
        $raw = $null
        try { $raw = [System.IO.File]::ReadAllText($pkg.FullName) } catch { continue }
        $rel = $pkg.FullName.Substring($Root.Length).TrimStart('\', '/')
        foreach ($bad in $IOC.badPackages) {
            $i = Find-Literal -Content $raw -Needle ('"' + $bad + '"')
            if ($i -ge 0) {
                Add-Finding -Severity 'CRITICAL' -Category 'Dependency' -File $rel `
                    -Line (Get-LineNumber $raw $i) `
                    -Indicator "Malicious npm package declared: $bad" `
                    -Evidence (Get-Snippet $raw $i 70)
            }
        }
    }
}

# Payloads have been found hidden inside fake font assets and executed via Node.
function Test-FontPayloads {
    param([string]$Root)

    # -Include is unreliable with -LiteralPath + -Recurse, so filter on extension here.
    $fonts = Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            if (@('.woff', '.woff2') -notcontains $_.Extension.ToLower()) { return $false }
            if (Test-ExcludedPath $_.FullName) { return $false }
            return ($_.Length -le $Script:MaxFileBytes)
        }

    foreach ($f in $fonts) {
        $ascii = $null
        # Paths over the Win32 limit throw from the .NET file APIs; skip rather than abort.
        try { $ascii = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($f.FullName)) }
        catch { continue }

        $rel = $f.FullName.Substring($Root.Length).TrimStart('\', '/')

        # A real WOFF/WOFF2 starts with the wOFF / wOF2 magic. Anything else under
        # a font extension is masquerading, whatever it turns out to contain.
        $magic = ''
        if ($ascii.Length -ge 4) { $magic = $ascii.Substring(0, 4) }
        if ($magic -ne 'wOFF' -and $magic -ne 'wOF2') {
            Add-Finding -Severity 'CRITICAL' -Category 'Payload' -File $rel -Line 0 `
                -Indicator 'Font asset is not a font (missing wOFF/wOF2 magic bytes)' `
                -Evidence "File starts with: $(Format-Evidence $magic 12)"
        }

        if ($ascii -match 'require\(|global\[|eval\(|child_process') {
            Add-Finding -Severity 'CRITICAL' -Category 'Payload' -File $rel -Line 0 `
                -Indicator 'JavaScript inside a font asset (fake-font sub-variant)' `
                -Evidence 'Font file contains executable JS tokens'
        }

        # Run the full signature battery over the disguised content so the variant
        # gets named, rather than only reporting that the file looks wrong.
        Test-PayloadSignatures -Content $ascii -Rel $rel

        $pad = [regex]::Match($ascii, '^\s{80,}')
        if ($pad.Success) {
            Add-Finding -Severity 'HIGH' -Category 'Structure' -File $rel -Line 1 `
                -Indicator "Leading padding: $($pad.Length) whitespace chars before content" `
                -Evidence 'Hides payload from casual inspection of the file head'
        }
    }
}

# The actor drops a canned skeleton - a whole .vscode folder plus a full
# public/fonts tree - into repos that have no business owning either. The genuine
# FontAwesome files are camouflage for the one fake. These fingerprints identify
# the kit itself rather than the payload, so they survive obfuscator rotation and
# fire even when the payload has already been cleaned out.
function Test-KitFingerprint {
    param([string]$Root)

    # FontAwesome ships solid at weight 900. A weight-400 solid file does not
    # exist upstream, so this filename is a campaign artifact by itself.
    foreach ($name in $IOC.kitFileNames) {
        $found = Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $name -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-ExcludedPath $_.FullName) }
        foreach ($f in $found) {
            Add-Finding -Severity 'CRITICAL' -Category 'Kit' `
                -File $f.FullName.Substring($Root.Length).TrimStart('\', '/') -Line 0 `
                -Indicator "Campaign artifact filename: $name" `
                -Evidence 'FontAwesome has no weight-400 solid face; this filename is attacker-generated'
        }
    }

    $tasks = Join-Path $Root '.vscode/tasks.json'
    if (Test-Path -LiteralPath $tasks) {
        $c = [System.IO.File]::ReadAllText($tasks)
        if ((Find-Literal $c $IOC.kitTaskLabel) -ge 0 -and (Find-Literal $c $IOC.kitTaskProbe) -ge 0) {
            Add-Finding -Severity 'CRITICAL' -Category 'Kit' -File '.vscode/tasks.json' -Line 1 `
                -Indicator 'Canned autorun task from the PolinRider kit' `
                -Evidence 'Label "eslint-check" with the cross-platform node probe'
        }
    }

    $settings = Join-Path $Root '.vscode/settings.json'
    if (Test-Path -LiteralPath $settings) {
        $c = [System.IO.File]::ReadAllText($settings)
        $matched = 0
        foreach ($k in $IOC.kitSettingsKeys) { if ((Find-Literal $c $k) -ge 0) { $matched++ } }
        if ($matched -ge 3) {
            Add-Finding -Severity 'HIGH' -Category 'Kit' -File '.vscode/settings.json' -Line 1 `
                -Indicator "Canned settings.json from the PolinRider kit ($matched/$($IOC.kitSettingsKeys.Count) markers)" `
                -Evidence 'Attacker template, not developer configuration'
        }
        # settings.json has no "tasks" object in its schema. A decoy one is cover
        # for the real task living next door in tasks.json.
        if ($c -match '"tasks"\s*:\s*\{' -and $c -match 'runOn') {
            Add-Finding -Severity 'HIGH' -Category 'Kit' -File '.vscode/settings.json' -Line 1 `
                -Indicator 'Decoy "tasks" block inside settings.json' `
                -Evidence 'Not a valid setting - plausible cover for the real autorun task'
        }
    }

    $launch = Join-Path $Root '.vscode/launch.json'
    if (Test-Path -LiteralPath $launch) {
        $c = [System.IO.File]::ReadAllText($launch)
        if ((Find-Literal $c $IOC.kitAwsProfile) -ge 0) {
            Add-Finding -Severity 'HIGH' -Category 'Kit' -File '.vscode/launch.json' -Line 1 `
                -Indicator 'Attacker template AWS profile in launch.json' `
                -Evidence $IOC.kitAwsProfile
        }
    }
}

# Per-victim IDs written by the actor's tooling. Tags still holding a template
# placeholder mean the tooling fired before allocating an ID.
function Test-VictimTag {
    param([string]$Content, [string]$Rel)

    foreach ($p in $IOC.victimTagPrefixes) {
        $i = Find-Literal -Content $Content -Needle $p
        if ($i -ge 0) {
            Add-Finding -Severity 'CRITICAL' -Category 'Payload' -File $Rel `
                -Line (Get-LineNumber $Content $i) `
                -Indicator 'PolinRider victim tag' `
                -Evidence (Get-Snippet $Content $i 40)
        }
    }
    foreach ($p in $IOC.victimTagPlaceholders) {
        $i = Find-Literal -Content $Content -Needle $p
        if ($i -ge 0) {
            Add-Finding -Severity 'CRITICAL' -Category 'Payload' -File $Rel `
                -Line (Get-LineNumber $Content $i) `
                -Indicator 'Un-substituted victim-tag placeholder' `
                -Evidence "Actor tooling artifact: $p"
        }
    }
}

# ---------------------------------------------------------------------------
# Host checks: npm's own install, and any live matching process.
#
# The repo is not the only place this campaign lands. The same payload has been
# found appended directly to npm's lib/cli.js - meaning every npm/npx call on
# the machine re-runs it - and confirmed running as a live node process with an
# open connection to its C2. Neither shows up in a scan of repo files, so these
# run separately, once per invocation rather than once per file.
#
# npm is never invoked to find these paths: requiring a compromised cli.js is
# what runs its payload, and `npm --version` does exactly that. Filesystem
# search only.
# ---------------------------------------------------------------------------

function Get-NpmCliCandidates {
    $candidates = New-Object System.Collections.ArrayList

    $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    if ($nodeCmd) {
        $nd = Split-Path $nodeCmd.Source -Parent
        foreach ($rel in @('node_modules\npm\lib\cli.js', '..\lib\node_modules\npm\lib\cli.js')) {
            $c = Join-Path $nd $rel
            if (Test-Path -LiteralPath $c) { $null = $candidates.Add((Resolve-Path $c).Path) }
        }
    }

    # Every nvm-windows version installed, active or not - a "clean" reinstall
    # has been observed reinfected within hours.
    $roots = @(
        (Join-Path $env:LOCALAPPDATA 'nvm'),
        (Join-Path $env:APPDATA 'npm'),
        'C:\Program Files\nodejs',
        'C:\nvm4w\nodejs'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -Recurse -File -Filter 'cli.js' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '[\\/]npm[\\/]lib[\\/]cli\.js$' } |
            ForEach-Object { $null = $candidates.Add($_.FullName) }
    }

    return @($candidates | Sort-Object -Unique)
}

function Test-HostNpmCli {
    $paths = Get-NpmCliCandidates
    foreach ($f in $paths) {
        if (-not (Test-Path -LiteralPath $f)) { continue }

        $ver = ''
        $pkgJson = Join-Path (Split-Path (Split-Path $f -Parent) -Parent) 'package.json'
        if (Test-Path -LiteralPath $pkgJson) {
            try {
                $ver = (Get-Content -LiteralPath $pkgJson -Raw | ConvertFrom-Json).version
            }
            catch {}
        }
        $label = if ($ver) { "npm $ver ($f)" } else { "npm ($f)" }

        $content = $null
        try { $content = [System.IO.File]::ReadAllText($f) } catch { continue }

        Test-PayloadSignatures -Content $content -Rel $label
        Test-NetworkIocs       -Content $content -Rel $label

        $bytes = (Get-Item -LiteralPath $f).Length
        if ($bytes -gt 4096) {
            $lines = $content -split "`n"
            $lineNo = 0
            foreach ($ln in $lines) {
                $lineNo++
                if ($ln.Length -lt 400) { continue }
                $pad = [regex]::Match($ln, '\s{80,}')
                if ($pad.Success -and ($pad.Index + $pad.Length) -lt ($ln.Length - 200)) {
                    $tail = $ln.Length - $pad.Index - $pad.Length
                    Add-Finding -Severity 'CRITICAL' -Category 'Host' -File $label -Line $lineNo `
                        -Indicator "npm is compromised - hidden payload appended to lib/cli.js" `
                        -Evidence "$($pad.Length) whitespace chars then $tail chars of code, $bytes bytes total"
                }
                break
            }
        }
    }
}

function Test-HostProcesses {
    $procs = Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        $cmd = $p.CommandLine
        if (-not $cmd) { continue }

        $hasInj = ($cmd.Contains($IOC.globalV1) -or $cmd.Contains($IOC.globalV2))
        $hasLoader = $cmd.Contains($IOC.globalReq) -and $cmd.Contains($IOC.globalMod)
        if ($hasInj -and $hasLoader) {
            Add-Finding -Severity 'CRITICAL' -Category 'Host' -File "PID $($p.ProcessId)" -Line 0 `
                -Indicator 'PolinRider loader running as a live process' `
                -Evidence 'Command line carries the injection marker with the require/module loader pair'
        }
        foreach ($ip in $IOC.c2Ips) {
            if ($cmd.Contains($ip)) {
                Add-Finding -Severity 'CRITICAL' -Category 'Host' -File "PID $($p.ProcessId)" -Line 0 `
                    -Indicator 'Live process connecting to a known PolinRider C2' -Evidence $ip
            }
        }
        if ($IOC.xorKeys) {
            foreach ($k in $IOC.xorKeys) {
                if ($cmd.Contains($k)) {
                    Add-Finding -Severity 'CRITICAL' -Category 'Host' -File "PID $($p.ProcessId)" -Line 0 `
                        -Indicator 'Live process carrying the PolinRider XOR decode key' -Evidence ''
                }
            }
        }
    }
}


# ---------------------------------------------------------------------------
# Editor-injection vector.
#
# Observed 2026-08-20: VS Code's own entry point patched, with a single import
# prepended to resources/app/out/main.js pulling in a sibling dropper
# (main.inz.cjs, 258 KB obfuscated) that spawns the loader from the MAIN
# process about two seconds after launch. It survives removing extensions,
# clearing tasks.json and disabling automatic tasks, because it is none of
# those - and it rewrites npm's cli.js on every start, which is why a cleaned
# npm reappears infected within minutes.
#
# The structural rule carries the detection: Microsoft ships main.js starting
# with its copyright banner, so ANY code before that banner is injected. That
# holds no matter which constants the actor rotates to next.
#
# Note the versioned layout - recent builds nest resources under a hashed
# directory (...\Microsoft VS Code\110a328ea5\resources\app), so a check that
# hardcodes ...\Microsoft VS Code\resources\app silently finds nothing and
# reads as clean.
# ---------------------------------------------------------------------------

function Get-VsCodeAppOutDirs {
    $roots = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Microsoft VS Code'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Microsoft VS Code Insiders'),
        'C:\Program Files\Microsoft VS Code',
        'C:\Program Files\Microsoft VS Code Insiders',
        '/usr/share/code',
        '/Applications/Visual Studio Code.app/Contents/Resources'
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    $found = New-Object System.Collections.ArrayList
    foreach ($root in $roots) {
        foreach ($pat in @('resources\app\out', '*\resources\app\out', 'app\out')) {
            $cands = @()
            try { $cands = Get-Item -Path (Join-Path $root $pat) -ErrorAction SilentlyContinue } catch {}
            foreach ($c in $cands) {
                if ($c -and (Test-Path -LiteralPath (Join-Path $c.FullName 'main.js'))) {
                    $null = $found.Add($c.FullName)
                }
            }
        }
    }
    return @($found | Sort-Object -Unique)
}

function Test-HostEditorInjection {
    foreach ($out in (Get-VsCodeAppOutDirs)) {
        $mainJs = Join-Path $out 'main.js'
        if (-not (Test-Path -LiteralPath $mainJs)) { continue }

        $label = "VS Code ($mainJs)"
        $head = ''
        try {
            $fs = [System.IO.File]::OpenRead($mainJs)
            $buf = New-Object byte[] 4096
            $n = $fs.Read($buf, 0, $buf.Length)
            $fs.Close()
            $head = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
        }
        catch { continue }

        # Structural: anything before Microsoft's banner did not ship with the editor.
        $bannerAt = $head.IndexOf('Copyright (C) Microsoft Corporation')
        if ($bannerAt -gt 0) {
            $prefix = $head.Substring(0, $bannerAt)
            if ($prefix -match '\b(import|require|createRequire|eval)\b') {
                Add-Finding -Severity 'CRITICAL' -Category 'Host' -File $label -Line 1 `
                    -Indicator 'VS Code entry point patched - code injected ahead of the Microsoft banner' `
                    -Evidence (Format-Evidence $prefix.Trim())
            }
        }

        # The dropper lands beside main.js; main.js.map is the only sibling
        # Microsoft ships, so any other main.* module here is unexpected.
        Get-ChildItem -LiteralPath $out -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^main\..+\.(cjs|mjs|js)$' -and $_.Name -ne 'main.js.map' } |
            ForEach-Object {
                Add-Finding -Severity 'CRITICAL' -Category 'Host' -File "VS Code ($($_.FullName))" -Line 0 `
                    -Indicator 'Unexpected module planted beside VS Code main.js' `
                    -Evidence "$($_.Length) bytes, written $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))"

                $c = $null
                try { $c = [System.IO.File]::ReadAllText($_.FullName) } catch {}
                if ($c) {
                    Test-PayloadSignatures -Content $c -Rel "VS Code ($($_.Name))"
                    Test-NetworkIocs       -Content $c -Rel "VS Code ($($_.Name))"
                }
            }

        # Signature sweep of main.js itself, in case the shape changes but the
        # constants do not.
        $full = $null
        try { $full = [System.IO.File]::ReadAllText($mainJs) } catch {}
        if ($full) {
            Test-PayloadSignatures -Content $full -Rel $label
            Test-NetworkIocs       -Content $full -Rel $label
        }
    }
}
function Test-GitHistory {
    param([string]$Root)

    $log = & git -C $Root log --all --format="%H%x09%s" -n 500 2>$null
    if (-not $log) { return }

    foreach ($line in $log) {
        $parts = $line -split "`t", 2
        if ($parts.Count -lt 2) { continue }
        if ($parts[1] -match 'auto[_ -]?push|LAST_COMMIT_DATE') {
            Add-Finding -Severity 'HIGH' -Category 'History' -File 'git log' -Line 0 `
                -Indicator "Suspicious commit subject: $($parts[1])" `
                -Evidence $parts[0].Substring(0, 12)
        }
    }
}

# ---------------------------------------------------------------------------
# Repository acquisition
# ---------------------------------------------------------------------------

function Resolve-RepoTarget {
    param([string]$Spec)

    if (Test-Path -LiteralPath $Spec -PathType Container) {
        return [pscustomobject]@{
            Path   = (Resolve-Path -LiteralPath $Spec).Path
            Temp   = $false
            Source = $Spec
        }
    }

    $url = $Spec
    if ($Spec -match '^[\w.-]+/[\w.-]+$') { $url = "https://github.com/$Spec" }
    if ($url -notmatch '^(https?://|git@|ssh://)') {
        throw "Not a directory and not a recognisable repo URL: $Spec"
    }

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('polinrider-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    Write-Host "Cloning $url ..." -ForegroundColor Cyan

    $cloneArgs = @('clone', '--quiet')
    if (-not $Deep) { $cloneArgs += @('--depth', '1') }
    $cloneArgs += @($url, $tmp)

    & git @cloneArgs
    if ($LASTEXITCODE -ne 0) {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        throw "git clone failed for $url (private repo, bad URL, or no network?)"
    }

    return [pscustomobject]@{ Path = $tmp; Temp = $true; Source = $url }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$target = $null
try {
    $target = Resolve-RepoTarget -Spec $Repo
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

$root = $target.Path

try {
    Write-Host ''
    Write-Host "PolinRider audit - $($target.Source)" -ForegroundColor Cyan
    Write-Host "Indicator set: $($IOC.version)"
    Write-Host ('-' * 62)

    $files = Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            if (Test-ExcludedPath $_.FullName) { return $false }
            if ($_.Length -gt $Script:MaxFileBytes) { return $false }
            # Every file under the size cap gets the signature pass, not just an
            # extension allow-list. The payload has already been found wearing a
            # .woff2 extension, so any allow-list is one rename away from useless.
            return $true
        }

    $scanned = 0
    foreach ($f in $files) {
        $content = $null
        try { $content = [System.IO.File]::ReadAllText($f.FullName) } catch { continue }
        $scanned++

        $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/')
        $isConfig = $IOC.configFiles -contains $f.Name

        # Documentation legitimately quotes these indicators - security notes,
        # incident write-ups, this tool's own README - so running the signature
        # passes over prose just makes the scanner report itself. The campaign
        # injects into executable config and assets, never into markdown.
        $isProse = $f.Extension.ToLower() -eq '.md'

        if (-not $isProse) {
            Test-PayloadSignatures -Content $content -Rel $rel
            Test-VictimTag         -Content $content -Rel $rel
            Test-NetworkIocs       -Content $content -Rel $rel
        }
        Test-StructuralAnomaly -Content $content -Rel $rel -Bytes $f.Length -IsConfig $isConfig
        Test-InvisibleUnicode  -Content $content -Rel $rel
    }

    Test-Artifacts      -Root $root
    Test-TasksJson      -Root $root
    Test-VsCodeSettings -Root $root
    Test-Dependencies -Root $root
    Test-FontPayloads   -Root $root
    Test-KitFingerprint -Root $root
    if ($Deep) { Test-GitHistory -Root $root }

    # Host checks are about this machine, not the repo just scanned - on by
    # default because the payload has been found living in npm's own install.
    if (-not $NoHostScan) {
        Test-HostNpmCli
        Test-HostProcesses
        Test-HostEditorInjection
    }

    $crit = @($Script:Findings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    $high = @($Script:Findings | Where-Object { $_.Severity -eq 'HIGH' }).Count

    $verdict = 'CLEAN'
    if ($crit -gt 0) { $verdict = 'COMPROMISED' }
    elseif ($high -gt 0) { $verdict = 'SUSPICIOUS' }
    elseif ($Script:Findings.Count -gt 0) { $verdict = 'REVIEW' }

    if ($Json) {
        [pscustomobject]@{
            source   = $target.Source
            verdict  = $verdict
            scanned  = $scanned
            critical = $crit
            high     = $high
            findings = @($Script:Findings)
        } | ConvertTo-Json -Depth 5
    }
    else {
        Write-Host "Files scanned: $scanned"
        Write-Host ''

        if ($Script:Findings.Count -eq 0) {
            Write-Host 'VERDICT: CLEAN - no PolinRider indicators found' -ForegroundColor Green
        }
        else {
            $order = @{ 'CRITICAL' = 0; 'HIGH' = 1; 'MEDIUM' = 2; 'LOW' = 3 }
            foreach ($f in ($Script:Findings | Sort-Object { $order[$_.Severity] }, File)) {
                $colour = 'Yellow'
                if ($f.Severity -eq 'CRITICAL') { $colour = 'Red' }
                elseif ($f.Severity -eq 'MEDIUM') { $colour = 'DarkYellow' }

                $loc = $f.File
                if ($f.Line -gt 0) { $loc = "$($f.File):$($f.Line)" }

                Write-Host ("[{0}] {1}" -f $f.Severity, $f.Indicator) -ForegroundColor $colour
                Write-Host ("         at {0}" -f $loc)
                if ($f.Evidence) { Write-Host ("         {0}" -f $f.Evidence) -ForegroundColor DarkGray }
            }

            Write-Host ''
            $vcolour = 'Yellow'
            if ($verdict -eq 'COMPROMISED') { $vcolour = 'Red' }
            Write-Host "VERDICT: $verdict  ($crit critical, $high high, $($Script:Findings.Count) total)" -ForegroundColor $vcolour

            Write-Host ''
            Write-Host 'Remediation:' -ForegroundColor Cyan
            Write-Host '  1. Strip the appended payload from flagged config files (everything after the real config).'
            Write-Host '  2. Delete the propagation artifacts and remove them from .gitignore.'
            Write-Host '  3. Remove flagged npm packages and reinstall from a verified lockfile.'
            Write-Host '  4. Rotate GitHub PATs, SSH keys, .env secrets and any wallet keys on affected hosts.'
            Write-Host '  5. Audit VS Code extensions and global npm packages for the original dropper.'
        }
    }

    if ($verdict -eq 'COMPROMISED' -or $verdict -eq 'SUSPICIOUS') { exit 1 }
    exit 0
}
finally {
    if ($target -and $target.Temp -and (Test-Path -LiteralPath $root)) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
