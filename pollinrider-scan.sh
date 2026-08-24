#!/bin/sh
# ---------------------------------------------------------------------------
# PolinRider scanner - SELF-CONTAINED, shared by the pre-commit and pre-push hooks.
#
#   pollinrider-scan.sh staged   scan what is about to be committed (pre-commit)
#   pollinrider-scan.sh tree     scan every tracked file, plus the host (pre-push)
#   pollinrider-scan.sh host     scan only the host: npm's own install + live
#                                processes. No repo required - runs anywhere.
#
# Exit 0 = clean, 1 = indicators found.
#
# No external files, no Node, no network. Only git/grep/awk/ps, so it behaves
# the same in Git Bash on Windows, macOS and Linux, and keeps working when the
# Node toolchain itself is the thing that is compromised. The one exception:
# on native Windows, process enumeration shells out to powershell.exe, because
# Git Bash's own `ps` only sees MSYS-spawned processes, not the wider Windows
# process list - and powershell.exe ships on every Windows install. It is used
# strictly to read process metadata (Get-CimInstance), never to execute
# anything found while scanning.
#
# DESIGN NOTE 1 - why almost nothing here is filename-based:
# The actor renames things. The payload has turned up as postcss.config.js, as
# fa-solid-400.woff2, appended directly to npm's own lib/cli.js, and inside a
# repo that owns no fonts at all. So every check that can be content-based is
# content-based. Filenames only pick which content test to run; they are never
# the finding.
#
# DESIGN NOTE 2 - why this uses git grep instead of a per-file loop:
# A per-file loop spawns ~8 processes per file. On a few thousand tracked files
# that is tens of thousands of spawns and the hook takes minutes on Windows.
# git grep searches the whole tree in one process, and `--cached` makes it read
# the index, which is exactly the content a pre-commit hook needs to judge.
#
# DESIGN NOTE 3 - why host checks stay out of pre-commit:
# Spawning powershell.exe and walking filesystem globs adds real latency -
# pre-commit is deliberately instant so it never becomes something developers
# reach for --no-verify to skip. Host checks run on push instead, where a few
# extra seconds is already the norm, and via the standalone `host` mode for a
# manual or scheduled deep check.
# ---------------------------------------------------------------------------

MODE=${1:-tree}
FOUND=0

if [ "$MODE" = "staged" ]; then CACHED=--cached; else CACHED=; fi

# Documentation legitimately quotes these indicators - incident notes, this
# tool's own README - so scanning prose only makes the scanner report itself.
EXCL=":(exclude)*.md :(exclude)*.markdown :(exclude).githooks/* :(exclude).husky/*"

report() {
    printf '  [%s] %s\n' "$1" "$2"
    if [ -n "$3" ]; then printf '        %s\n' "$3"; fi
    FOUND=1
}

# Signature fragments are concatenated at runtime rather than written as whole
# literals, so this file does not itself read as a malware sample to on-access AV.
M1='rmcej'"%otb%"
M2='Cot'"%3t=shtP"
GV1='global'"['!']"
GV2='global'"['_V']"
GR='global'"['r']"
GM='global'"['m']"
D1='_$_'"1e42"
# Split so this file does not contain the literals it hunts for. Without this the
# scanner reports itself, and excluding its own path instead would leave a hole an
# attacker could hide a payload in.
S1='285'"7687"; S2='266'"7686"; S3='111'"1436"; S4='389'"6884"
SEEDS="$S1 $S2 $S3 $S4"
TAG1='global'".i=\"A8-"
TAG2='global'".i=\"A9-"
# Confirmed live in this campaign: the C2 the stage-2 loader calls home to, and
# the XOR key it uses to decode the response body. Both pulled from a payload
# caught actively running on this machine, not from published research.
C2IP='166.88'".134.62"
XK='q4FZkxX{!h,Sr3'"=@"

# In staged mode look only at the paths actually being committed. git grep
# --cached otherwise searches the entire index, which makes a pre-commit hook pay
# the cost of a full-tree scan on every commit.
SCOPE="."
if [ "$MODE" = "staged" ]; then
    SCOPE=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)
    if [ -z "$SCOPE" ]; then
        printf '\npolinrider: nothing staged - clean\n\n'
        exit 0
    fi
fi

# One git grep over the scope. -a so binary assets are searched too: that is what
# catches a payload renamed into a .woff2.
gg() { git grep $CACHED -l -a -F "$@" -- $SCOPE $EXCL 2>/dev/null; }

show() {
    if [ "$MODE" = "staged" ]; then git show ":$1" 2>/dev/null; else cat "$1" 2>/dev/null; fi
}

# ---------------------------------------------------------------------------
# Host checks: npm's own install, and any live matching process.
#
# The repo is not the only place this campaign lands. The same payload has been
# found appended directly to npm's lib/cli.js - meaning every npm or npx
# invocation on the machine re-runs it - and confirmed running as a live node
# process with an open connection to its C2. Neither of those shows up in any
# git diff, which is why they need their own checks.
# ---------------------------------------------------------------------------

detect_os() {
    case "$(uname -s 2>/dev/null)" in
        Linux*)               echo linux ;;
        Darwin*)              echo macos ;;
        CYGWIN*|MINGW*|MSYS*) echo windows ;;
        *)                    echo unknown ;;
    esac
}

# Locate every npm install this machine has, active or not. A "clean" reinstall
# has been observed reinfected within hours, so all versions are worth checking,
# not just the one currently on PATH. Filesystem search only - npm is never
# invoked, because requiring a compromised cli.js is what runs its payload, and
# `npm --version` does exactly that.
npm_cli_candidates() {
    node_bin=$(command -v node 2>/dev/null)
    if [ -n "$node_bin" ]; then
        nd=$(dirname "$node_bin")
        for c in "$nd/node_modules/npm/lib/cli.js" "$nd/../lib/node_modules/npm/lib/cli.js"; do
            [ -f "$c" ] && printf '%s\n' "$c"
        done
    fi

    for c in \
        "$HOME"/.nvm/versions/node/*/lib/node_modules/npm/lib/cli.js \
        "$HOME"/.volta/tools/image/node/*/lib/node_modules/npm/lib/cli.js \
        /usr/local/lib/node_modules/npm/lib/cli.js \
        /usr/lib/node_modules/npm/lib/cli.js \
        /opt/homebrew/lib/node_modules/npm/lib/cli.js \
        /usr/local/Cellar/node/*/lib/node_modules/npm/lib/cli.js \
        "$LOCALAPPDATA"/nvm/*/node_modules/npm/lib/cli.js \
        "$APPDATA"/npm/node_modules/npm/lib/cli.js \
        "/c/Program Files/nodejs/node_modules/npm/lib/cli.js" \
        "/c/nvm4w/nodejs/node_modules/npm/lib/cli.js"
    do
        [ -f "$c" ] && printf '%s\n' "$c"
    done
}

scan_npm_cli() {
    candidates=$(npm_cli_candidates 2>/dev/null | sort -u)
    [ -n "$candidates" ] || return

    while IFS= read -r f; do
        [ -f "$f" ] || continue

        ver=""
        pkgjson=$(dirname "$(dirname "$f")")/package.json
        if [ -f "$pkgjson" ]; then
            ver=$(grep -m1 '"version"' "$pkgjson" 2>/dev/null | sed -E 's/.*"version"[^"]*"([^"]+)".*/\1/')
        fi
        label="npm${ver:+ $ver} ($f)"

        has() { grep -qaF -- "$1" "$f" 2>/dev/null; }

        if has "$M1" || has "$M2"; then
            report CRITICAL "npm is compromised - payload signature in $label" \
                "Every npm/npx invocation on this machine re-runs this"
        fi
        if { has "$GV1" || has "$GV2"; } && has "$GR" && has "$GM"; then
            report CRITICAL "npm is compromised - loader globals in $label" \
                "Injection marker with require/module loader pair"
        fi
        if has "$C2IP"; then
            report CRITICAL "npm is compromised - known C2 address in $label" "$C2IP"
        fi
        if has "$XK"; then
            report CRITICAL "npm is compromised - XOR decode key in $label" ""
        fi

        pad=$(awk '
            length($0) < 400 { next }
            match($0, /[ \t][ \t][ \t]+/) {
                if (RLENGTH >= 80) {
                    tail = length($0) - RSTART - RLENGTH + 1
                    if (tail > 200) { print RLENGTH ":" tail; exit }
                }
            }' "$f" 2>/dev/null)
        if [ -n "$pad" ]; then
            p=${pad%%:*}; t=${pad#*:}
            bytes=$(wc -c < "$f" 2>/dev/null | tr -d ' ')
            report CRITICAL "npm is compromised - hidden payload appended to $label" \
                "$p whitespace chars then $t chars of code, $bytes bytes total"
        fi
    done <<CLIEOF
$candidates
CLIEOF
}

# List node processes and check their command line for the loader pattern.
# Read-only: this reads process metadata, it never touches or signals the process.
# Editor-injection vector. Observed 2026-08-20: VS Code's own entry point
# patched, with a single import prepended to resources/app/out/main.js loading a
# sibling dropper (main.inz.cjs) that spawns the loader from the MAIN process at
# startup and re-infects npm on every launch. It survives removing extensions,
# clearing tasks.json and disabling automatic tasks, because it is none of those.
#
# Both rules are structural, so they survive the constant rotation the actor
# performed in April 2026:
#   1. Microsoft ships main.js beginning with its /*! copyright banner, so any
#      code ahead of that banner was injected.
#   2. main.js.map is the only sibling Microsoft ships beside main.js.
#
# Layout differs per platform, and recent Windows builds nest resources under a
# hashed directory - a check hardcoding .../Microsoft VS Code/resources/app finds
# nothing there and reads as clean, which is how this was first missed.
vscode_out_dirs() {
    bases="
${LOCALAPPDATA:-$HOME/AppData/Local}/Programs/Microsoft VS Code
${LOCALAPPDATA:-$HOME/AppData/Local}/Programs/Microsoft VS Code Insiders
${LOCALAPPDATA:-$HOME/AppData/Local}/Programs/VSCodium
/c/Program Files/Microsoft VS Code
/c/Program Files/Microsoft VS Code Insiders
/Applications/Visual Studio Code.app/Contents/Resources
/Applications/Visual Studio Code - Insiders.app/Contents/Resources
$HOME/Applications/Visual Studio Code.app/Contents/Resources
/usr/share/code
/usr/share/code-insiders
/usr/share/codium
/opt/visual-studio-code
/opt/vscode
/snap/code/current/usr/share/code
/var/lib/flatpak/app/com.visualstudio.code/current/active/files/share/code
$HOME/.local/share/code
"
    while IFS= read -r b; do
        [ -n "$b" ] || continue
        [ -d "$b" ] || continue
        # Plain layout, one hashed level (Windows), and the macOS app layout.
        for d in "$b"/resources/app/out "$b"/*/resources/app/out "$b"/app/out; do
            [ -f "$d/main.js" ] && printf '%s\n' "$d"
        done
    done <<VSCEOF
$bases
VSCEOF
    # Remote/server installs keep a versioned bin directory per commit.
    for d in "$HOME"/.vscode-server/bin/*/out "$HOME"/.vscode-server-insiders/bin/*/out; do
        [ -f "$d/main.js" ] && printf '%s\n' "$d"
    done
}

scan_editor_injection() {
    outdirs=$(vscode_out_dirs 2>/dev/null | sort -u)
    [ -n "$outdirs" ] || return

    # Fed by heredoc, not a pipe: a piped while runs in a subshell, so report()
    # would print findings while FOUND stayed 0 and the hook let the push through.
    while IFS= read -r out; do
        [ -n "$out" ] || continue
        main="$out/main.js"
        [ -f "$main" ] || continue

        # Everything ahead of the banner. Parameter expansion rather than awk so
        # there is no regex escaping to get wrong across awk implementations.
        head4k=$(head -c 4096 "$main" 2>/dev/null)
        prefix=${head4k%%/\*!*}
        [ "$prefix" = "$head4k" ] && prefix=""

        case "$prefix" in
            *import*|*require*|*createRequire*|*eval*)
                report CRITICAL \
                    "VS Code entry point patched - code injected ahead of the Microsoft banner" \
                    "$main"
                ;;
        esac

        for f in "$out"/main.*.cjs "$out"/main.*.mjs; do
            [ -f "$f" ] || continue
            case "$f" in *.js.map) continue ;; esac
            report CRITICAL \
                "Unexpected module planted beside VS Code main.js" \
                "$f ($(wc -c < "$f" 2>/dev/null | tr -d ' ') bytes)"
        done
    done <<OUTEOF
$outdirs
OUTEOF
}

scan_processes() {
    os=$(detect_os)
    ps_out=""
    case "$os" in
        linux|macos)
            ps_out=$(ps -eo pid,args 2>/dev/null)
            ;;
        windows)
            if command -v powershell.exe >/dev/null 2>&1; then
                ps_out=$(powershell.exe -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" -ErrorAction SilentlyContinue | ForEach-Object { \$_.ProcessId.ToString() + [char]9 + \$_.CommandLine }" 2>/dev/null)
            fi
            ;;
        *)
            ps_out=$(ps -ef 2>/dev/null)
            ;;
    esac
    [ -n "$ps_out" ] || return

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        printf '%s' "$line" | grep -qi 'node' 2>/dev/null || continue
        pid=$(printf '%s\n' "$line" | awk '{print $1}')

        hasl() { printf '%s' "$line" | grep -qF -- "$1" 2>/dev/null; }

        if { hasl "$GV1" || hasl "$GV2"; } && hasl "$GR" && hasl "$GM"; then
            report CRITICAL "PolinRider loader running as a live process (PID $pid)" \
                "Command line carries the injection marker with the require/module loader pair"
        fi
        if hasl "$C2IP"; then
            report CRITICAL "Live process connecting to the known PolinRider C2 (PID $pid)" "$C2IP"
        fi
        if hasl "$XK"; then
            report CRITICAL "Live process carrying the PolinRider XOR decode key (PID $pid)" ""
        fi
    done <<PSEOF
$ps_out
PSEOF
}

case "$MODE" in
    staged) printf '\npolinrider: scanning staged changes...\n' ;;
    host)   printf '\npolinrider: scanning host - npm install and live processes...\n' ;;
    *)      printf '\npolinrider: scanning tracked files and host...\n' ;;
esac

if [ "$MODE" != "host" ]; then

# --- 1-3. Signature pass. --------------------------------------------------
# One grep for every indicator at once to find candidate files. In the normal
# case nothing matches and the whole pass costs a single git grep; only the few
# files that hit are then examined precisely.
CANDIDATES=$(gg -e "$M1" -e "$M2" -e "$GV1" -e "$GV2" -e "$D1" \
                -e "$TAG1" -e "$TAG2" \
                -e "$S1" -e "$S2" -e "$S3" -e "$S4")

for f in $CANDIDATES; do
    has() { git grep $CACHED -q -a -F -e "$1" -- "$f" 2>/dev/null; }

    if has "$M1" || has "$M2"; then
        report CRITICAL "PolinRider obfuscator signature in $f" "Marker string present"
    fi

    # Injection marker with the require/module loader pair. Survives even when
    # the shuffle seeds do not, which is how real samples evaded signature rules.
    if { has "$GV1" || has "$GV2"; } && has "$GR" && has "$GM"; then
        report CRITICAL "PolinRider loader globals in $f" \
            "Injection marker with require/module loader pair"
    fi

    if has "$D1"; then
        report HIGH "PolinRider decoder function in $f" ""
    fi

    for s in $SEEDS; do
        if has "$s"; then
            report HIGH "PolinRider shuffle seed in $f" "Seed $s"
            break
        fi
    done

    if has "$TAG1" || has "$TAG2"; then
        report CRITICAL "PolinRider victim tag in $f" "Per-victim ID written by the actor's tooling"
    fi

    if has "$C2IP"; then
        report CRITICAL "Known PolinRider C2 address in $f" "$C2IP"
    fi
    if has "$XK"; then
        report CRITICAL "PolinRider XOR decode key in $f" ""
    fi
done

# --- 4. The padding trick, anywhere. ----------------------------------------
# A long whitespace run followed by a large block of code, so the payload sits
# off the right edge of the editor. Signature- and filename-independent, so it
# still fires on a rotated variant in a renamed file. Minified bundles contain no
# 80-character whitespace runs, so this does not collide with long lines.
for f in $(git grep $CACHED -l -a -E "[ ]{80,}" -- $SCOPE $EXCL 2>/dev/null); do
    hit=$(show "$f" | awk '
        match($0, /[ \t][ \t][ \t]+/) {
            if (RLENGTH >= 80) {
                tail = length($0) - RSTART - RLENGTH + 1
                if (tail > 200) { print NR ":" RLENGTH ":" tail; exit }
            }
        }' 2>/dev/null)
    if [ -n "$hit" ]; then
        ln=${hit%%:*}; rest=${hit#*:}; pad=${rest%%:*}; tail=${rest#*:}
        report CRITICAL "Hidden appended payload in $f (line $ln)" \
            "$pad whitespace chars then $tail chars of code - pushed off the right margin"
    fi
done

# --- 5. Every font, by content. ---------------------------------------------
# The actor can name the file anything; what it cannot do is make a Node script
# look like a real font binary.
for f in $(git ls-files '*.woff' '*.woff2' '*.ttf' '*.otf' '*.ttc' '*.eot' 2>/dev/null); do
    tmp=$(mktemp 2>/dev/null || echo "/tmp/prf$$")
    show "$f" > "$tmp" 2>/dev/null
    [ -s "$tmp" ] || { rm -f "$tmp"; continue; }

    # A real font is binary. One that is entirely printable text is a script.
    if ! LC_ALL=C grep -qa '[^[:print:][:space:]]' "$tmp" 2>/dev/null; then
        report CRITICAL "Font asset contains no binary data: $f" \
            "Entirely printable text - a script wearing a font extension"
    fi
    if grep -qaE 'require\(|global\[|eval\(|child_process|process\.env|Buffer\.from|spawn\(' "$tmp" 2>/dev/null; then
        report CRITICAL "JavaScript inside font asset: $f" "Executable tokens in a binary asset"
    fi
    # Real fonts start with format magic, never with whitespace.
    if head -c 1 "$tmp" 2>/dev/null | LC_ALL=C grep -qa '[[:space:]]' 2>/dev/null; then
        report CRITICAL "Font asset starts with whitespace: $f" \
            "Padding used to hide the payload from a glance at the file head"
    fi
    rm -f "$tmp"
done

# --- 6. Propagation artifacts and .gitignore cloaking. ---------------------
for a in temp_auto_push.bat config.bat temp_interactive_push.bat; do
    if [ -f "$a" ]; then
        report CRITICAL "Propagation artifact present: $a" \
            "Evidence of compromise even if the payload was cleaned"
    fi
    if [ -f .gitignore ] && grep -qx "$a" .gitignore 2>/dev/null; then
        report HIGH "$a is hidden by .gitignore" \
            "Attacker cloaking - it will not show in git status"
    fi
done
if [ -f .gitignore ] && grep -qx '\.gitignore' .gitignore 2>/dev/null; then
    report HIGH ".gitignore ignores itself" \
        "Hides the attacker's own edits to .gitignore from git status"
fi

# --- 7. The canned kit. -----------------------------------------------------
# A whole .vscode folder, often with a full public/fonts tree, dropped into repos
# that have no business owning either. Fires even after the payload is removed.
if [ -f .vscode/tasks.json ]; then
    t=.vscode/tasks.json
    if grep -q 'folderOpen' "$t" 2>/dev/null; then
        if grep -qE '(node|deno|bun|python3?)[^"]*\.(woff2?|ttf|otf|eot|png|jpe?g|ico|dat|bin|svg)' "$t" 2>/dev/null; then
            report CRITICAL "Autorun task executes a non-code asset" \
                "$t runs an interpreter against a disguised payload"
        elif grep -qE 'curl|wget|Invoke-WebRequest|bash -c' "$t" 2>/dev/null; then
            report CRITICAL "Autorun task fetches and executes remote content" "$t"
        fi
    fi
    if grep -q '"label": "eslint-check"' "$t" 2>/dev/null &&
       grep -q 'command -v node' "$t" 2>/dev/null; then
        report CRITICAL "Canned autorun task from the PolinRider kit" \
            'Label "eslint-check" with the cross-platform node probe'
    fi
fi
if [ -f .vscode/settings.json ]; then
    s=.vscode/settings.json
    if grep -q '"task.allowAutomaticTasks"[[:space:]]*:[[:space:]]*true' "$s" 2>/dev/null; then
        report HIGH "task.allowAutomaticTasks is enabled" \
            "Removes VS Code's confirmation prompt before folderOpen tasks run"
    fi
    if grep -q '"tasks"[[:space:]]*:[[:space:]]*{' "$s" 2>/dev/null && grep -q 'runOn' "$s" 2>/dev/null; then
        report HIGH 'Decoy "tasks" block inside settings.json' \
            "Not a valid setting - cover for the real autorun task next door"
    fi
fi
if [ -f .vscode/launch.json ] && grep -q 'flo-ct-flo360' .vscode/launch.json 2>/dev/null; then
    report HIGH "Attacker template AWS profile in .vscode/launch.json" \
        "flo-ct-flo360 - artifact of the actor's project template"
fi

# --- 8. Known malicious npm packages. --------------------------------------
for p in tailwind-mainanimation tailwind-autoanimation tailwind-animationbased \
         tailwindcss-style-animate tailwindcss-typography-style \
         tailwindcss-style-modify tailwindcss-animate-style; do
    for f in $(git grep $CACHED -l -F -e "\"$p\"" -- $SCOPE 2>/dev/null); do
        report CRITICAL "Malicious npm package declared in $f" "$p"
    done
done

fi
# end of repo-scoped checks (MODE != host)

# --- 9. Host checks: npm's own install, and any live matching process. -----
# Runs on push (tree) and on demand (host). Skipped for pre-commit - see
# DESIGN NOTE 3 above.
if [ "$MODE" = "tree" ] || [ "$MODE" = "host" ]; then
    scan_npm_cli
    scan_processes
    scan_editor_injection
fi

# --- Verdict ---------------------------------------------------------------
if [ "$FOUND" -ne 0 ]; then
    printf '\n'
    case "$MODE" in
        staged)
            printf 'COMMIT BLOCKED - PolinRider indicators found.\n'
            printf '\n'
            printf 'Do not commit this. Once it is in a commit it is in your history and\n'
            printf 'reflog even if the push is stopped later.\n'
            printf '\n'
            printf 'Override only for a confirmed false positive: git commit --no-verify\n'
            ;;
        host)
            printf 'HOST COMPROMISED - PolinRider indicators found on this machine.\n'
            printf '\n'
            printf 'This is not specific to any repository. npm itself, or a live process, is\n'
            printf 'carrying the payload. Kill the process(es) above, repair or reinstall npm,\n'
            printf 'and rotate credentials used from this machine before trusting further\n'
            printf 'commits or pushes made from it.\n'
            ;;
        *)
            printf 'PUSH BLOCKED - PolinRider indicators found.\n'
            printf '\n'
            printf 'This repo or this machine has been compromised before. Do not push until\n'
            printf 'both are clean.\n'
            printf '\n'
            printf 'Override only for a confirmed false positive: git push --no-verify\n'
            ;;
    esac
    printf '\n'
    exit 1
fi

printf 'polinrider: clean\n\n'
exit 0
