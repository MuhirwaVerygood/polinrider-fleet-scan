# polinrider-fleet-scan

Scans every repository across one or more GitHub owners for the **PolinRider**
supply-chain campaign, and opens (but never merges) a cleanup pull request for
anything infected.

PolinRider is a DPRK-attributed campaign that has been observed shipping as a
fake FontAwesome file (`fa-solid-400.woff2`), appended directly to legitimate
config files behind a long run of whitespace, and even injected into npm's own
`cli.js` so that every `npm`/`npx` invocation on an infected machine re-runs
it. It propagates further via a canned `.vscode/tasks.json` that auto-runs on
folder open. See [audit-pollinrider.ps1](audit-pollinrider.ps1) for the full,
cited indicator set.

## What it does

Three passes, run in order:

1. **Enumerate** — list every repo under each `-Owners` value via `gh repo
   list` (or take an explicit `-Repos owner/name` list instead).
2. **Scan** — run [audit-pollinrider.ps1](audit-pollinrider.ps1) read-only
   against a shallow clone of each repo. This is the same detector this
   project's own pre-commit/pre-push hooks use, so a repo judged clean here is
   clean by the same standard everywhere else.
3. **Repair** (`-Fix` only) — for anything `COMPROMISED` or `SUSPICIOUS`,
   clone persistently, strip what can be removed with confidence, install the
   same git-hook gate the rest of this toolkit uses, commit, push to a new
   `polinrider-cleanup-<timestamp>` branch, and open a pull request. **It
   stops there.**

## Why it never auto-merges

Every PR this script opens is left for a human to review and merge. That is
not a caveat added after the fact — it is the reason the repair pass exists as
a separate, gated step at all.

Real cleanups run during this project's own incident response needed a human
in the loop more than once:

- One repo's `.vscode/settings.json` mixed the campaign's two injected keys in
  with a developer's real Java and TypeScript settings. Getting that right
  meant parsing the file as an object and removing exactly two keys — never
  regexing or deleting the file outright. A different repo's `settings.json`
  might not parse cleanly at all (JSONC comments, trailing commas, hand
  edits); when that happens this tool flags it for manual review instead of
  guessing.
- `.vscode/launch.json` routinely holds real, unrelated debug configurations
  sitting right next to the campaign's injected one. This tool only ever
  flags `launch.json` — it will never edit it — because deciding which array
  entry is safe to delete needs a human who knows what the file is for.
- A GitOps values file needed a human to confirm which change was cosmetic
  cargo (safe to delete) and which was a live deployment path (not safe to
  touch), something no static scan of that repo alone could have told you.

Fleet-wide auto-merge across repositories nobody has looked at turns exactly
this kind of judgment call into an unattended one. A false positive, or a
correct finding with an unsafe automated fix, becomes a real incident instead
of a PR sitting in someone's review queue. So: this tool scans everything,
cleans up what it's confident about, and hands you a PR. You merge it.

## Prerequisites

- **PowerShell** — Windows PowerShell 5.1 (ships with every Windows install)
  or PowerShell 7+.
- **[GitHub CLI (`gh`)](https://cli.github.com/)**, authenticated:
  `gh auth login`, then `gh auth status` should succeed.
- **git** on `PATH`.

No Node, no other dependencies. All detector logic is vendored into this
directory (see below) so the project is self-contained — it does not depend on
being checked out next to anything else.

## Usage

```powershell
# Report only - scan every repo you or an org owns, change nothing.
.\fleet-scan.ps1 -Owners MyGithubUsername

# Scan several owners/orgs in one run.
.\fleet-scan.ps1 -Owners MyOrg,MyOtherOrg,MyGithubUsername

# Scan and open cleanup PRs for anything found (prompts once before touching anything).
.\fleet-scan.ps1 -Owners MyOrg -Fix

# Non-interactive (CI/scheduled): skip the confirmation prompt.
.\fleet-scan.ps1 -Owners MyOrg -Fix -Force

# Re-check one or two specific repos instead of a whole account.
.\fleet-scan.ps1 -Repos MyOrg/some-repo,MyOrg/other-repo -Fix
```

Useful flags:

| Flag | Effect |
|---|---|
| `-Owners <user/org...>` | Enumerate and scan every repo under these owners. |
| `-Repos <owner/name...>` | Scan exactly these repos instead of enumerating. |
| `-Fix` | After scanning, repair and open PRs for anything found. Without it, the run is read-only. |
| `-Force` | Skip the confirmation prompt before the repair pass (for scheduled runs). |
| `-IncludeForks` | Also scan forks (skipped by default — a fork's upstream is normally someone else's problem). |
| `-IncludeArchived` | Also scan archived repos (skipped by default). |
| `-MaxRepos <n>` | Safety cap on total repos scanned across all owners. Default 200. |
| `-OutDir <path>` | Where clones and the JSON report go. Defaults to a temp dir, deleted afterward. |
| `-KeepClones` | Don't delete the working clones afterward — useful for inspecting a repair before its PR is reviewed. |

Exit code is `0` if every repo scanned clean, `1` if anything was found
(regardless of whether `-Fix` was passed), `2` on a setup error (`gh` not
authenticated, no `-Owners`/`-Repos` given, etc.) — so it's safe to wire into
a scheduled job and alert on non-zero.

## What gets fixed automatically vs. flagged for review

Fixed automatically, only on a confident content-based match (never on
filename alone):

- The fake font payload (verified by content — not simply anything named
  `fa-solid-400.woff2`, actually checked for missing font magic bytes and
  embedded JavaScript, so a legitimately renamed font is never touched)
- The canned `.vscode/tasks.json` autorun kit
- The two campaign-injected keys inside `.vscode/settings.json`, leaving
  every other setting in the file untouched
- Known propagation artifacts (e.g. `temp_auto_push.bat`) and the `.gitignore`
  lines added to hide them
- Installing this project's own commit/push detection gate into `.githooks/`

Always flagged for manual review, never auto-edited:

- `.vscode/launch.json` (real debug configs routinely sit next to the
  injected one)
- A `settings.json` that matches enough indicators to be suspicious but
  doesn't parse cleanly
- A generic `folderOpen` task that isn't a confirmed match for the known kit

## Files in this project

| File | Purpose |
|---|---|
| `fleet-scan.ps1` | The fleet-wide entry point: enumerate → scan → repair → PR. |
| `audit-pollinrider.ps1` | Deep, read-only detector. Can also be run standalone: `.\audit-pollinrider.ps1 -Repo <url-or-path>`. |
| `pollinrider-scan.sh` | POSIX detector shared by the git hooks below — no Node, no network, works the same on Windows/macOS/Linux. |
| `hook-pre-commit.sh`, `hook-pre-push.sh` | Installed into a repo's `.githooks/` by the repair pass, and usable standalone in any repo (`git config core.hooksPath .githooks`). |
| `iocs.b64` | Base64-encoded indicator set — the single source of truth both detectors read from, so the fixer can never drift from what the scanner actually looks for. |

## Signature provenance

Every indicator in `iocs.b64` and every check in `audit-pollinrider.ps1` is
content-based where possible, not filename-based — the actor renames the
payload (it has turned up as `postcss.config.js`, as a font file, and
appended directly to npm's own `cli.js`). Indicators were gathered from live
incident response, including a payload sample caught actively running with an
open connection to its C2. See the comments in `audit-pollinrider.ps1` for
per-indicator detail.
