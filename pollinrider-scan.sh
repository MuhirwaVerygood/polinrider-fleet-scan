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

# ---------------------------------------------------------------------------
# 2026-09 variant, from a live sample force-pushed over a repo's initial commit
# (identical subject + author-date to the real commit; committer timezone did
# not match the author's). The payload was a TAB-indented JS blob wearing a
# FontAwesome name that is not a real weight, dropped beside genuine fa-* files
# in a repo that owns no web front end, and auto-run by a hidden folderOpen
# editor task. What changed vs earlier samples:
#  - concealment switched from spaces to tabs (evades a spaces-only prefilter)
#  - the require re-expose uses dot-notation assignment, not the bracket form
#  - the victim tag is single-quoted with spaces around the '='
#  - no hard-coded C2 IP: the loader reads an Ethereum wallet's last transaction
#    via public RPC / a chain indexer and decodes two IPv4s from the tx target,
#    then pulls stage 3 over an HTTP header and re-execs via a detached child.
#
# Every literal below is split across two quoted segments so this file does not
# itself contain a matchable indicator string (the rest of the file does the
# same - see the note by M1/M2).
SK2='y-p_>d$0B'"&@^1aQk"                  # second stage-3 loader key
LP1='4'"43/0x/cls"; LP2='4'"43/0x/ls"    # stage-3 URL path tails
X3H='x-payload'"-b64"                     # stage-3 delivery header
BSC='eth.block'"scout.com/api"            # on-chain indexer used as a C2 dead-drop
DDW='0xa322E5f3D311D3080e6'"f0121063e9aDC2490Ef1a"  # dead-drop wallet (rotatable)
AWSP='flo-ct'"-flo360"                    # actor project-template AWS profile
PROP2='branch_'"structure.json"          # propagation/recon artifact (with the .bat pair)
OC1='eth_get'"BlockByNumber"; OC2='eth_get'"TransactionCount"; OC3='NONCE_'"FANOUT"

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

        # Any extension, not just .cjs/.mjs - the dropper has also turned up as
        # main.js.inz.orig (a backup of the pre-patch original, dropped by the
        # injector itself before it overwrites main.js). main.js.map is the
        # only sibling Microsoft ships, so anything else named main.* here is
        # unexpected regardless of what comes after "main.".
        for f in "$out"/main.*; do
            [ -f "$f" ] || continue
            case "$f" in */main.js|*/main.js.map) continue ;; esac
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
                -e "$S1" -e "$S2" -e "$S3" -e "$S4" \
                -e "$SK2" -e "$LP1" -e "$LP2" -e "$X3H" -e "$BSC" -e "$DDW" -e "$AWSP")

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
    if has "$XK" || has "$SK2"; then
        report CRITICAL "PolinRider stage-3 loader key in $f" "XOR key for the encrypted stage-3 body"
    fi
    if has "$LP1" || has "$LP2"; then
        report CRITICAL "PolinRider stage-3 URL path in $f" "Fixed loader path on the resolved C2, port 443"
    fi
    if has "$X3H"; then
        report HIGH "PolinRider stage-3 delivery header in $f" "Encrypted stage-3 body carried base64 in an HTTP response header"
    fi
    if { has "$BSC" || has "$DDW"; } && has "require("; then
        report CRITICAL "On-chain C2 dead-drop resolver in $f" \
            "Reads an Ethereum wallet's last tx to derive its C2 - no hard-coded IP to grep for"
    fi
    if has "$AWSP"; then
        report HIGH "Actor project-template AWS profile in $f" "$AWSP - artifact of the actor's kit"
    fi
    if has "$PROP2"; then
        report HIGH "PolinRider propagation/recon artifact referenced in $f" "$PROP2"
    fi
done

# --- 3b. 2026-09 loader variant: regex signatures. -------------------------
# gg above is fixed-string only. These catch the dot-notation require re-expose,
# the single-quoted victim tag, the hidden detached re-spawn, and the on-chain
# resolver - each of which survives the literal rotation the actor does between
# victims. Content is read from the index in staged mode, from the tree otherwise.
RX_DOTGLOB='global\.[rmi][[:space:]]*=[[:space:]]*(require|module|.?[A-Za-z_.])'
RX_TAG3='global\.i[[:space:]]*=[[:space:]]*.?A[0-9]-[A-Za-z0-9*#]'
# no backreferences: BSD/macOS grep -E does not support them
RX_RESPAWN='spawn\(["'\'']node["'\''],[[:space:]]*\[["'\'']-e["'\'']'
RX_HIDE='detached:[[:space:]]*(!0|true)[^}]*(windowsHide|stdio)'
RX_CHAIN="$OC1|$OC2|$OC3|RPC_""ENDPOINTS|eth_""blockNumber"
RX_EXECSINK='eval\(|new Function\(|Function\(["'\'']|spawn\(|execSync\(|child_process'
for f in $(git grep $CACHED -l -a -E -e "$RX_TAG3" -e "$RX_RESPAWN" -e "$RX_CHAIN" -- $SCOPE $EXCL 2>/dev/null); do
    c=$(show "$f")
    [ -n "$c" ] || continue
    m() { printf '%s' "$c" | grep -qaE "$1"; }

    if m "$RX_TAG3" && m 'require|global\.[rm]'; then
        report CRITICAL "PolinRider victim tag (2026-09 form) in $f" \
            "single-quoted per-victim id assignment beside a require/module re-expose"
    fi
    if m "$RX_RESPAWN" && m "$RX_HIDE"; then
        report CRITICAL "Hidden detached re-spawn in $f" \
            "child node -e spawn, detached, stdio ignored, window hidden, then unref'd"
    fi
    if m "$RX_DOTGLOB" && m 'require' && m "$RX_EXECSINK"; then
        report CRITICAL "Loader globals (dot notation) with an exec sink in $f" \
            "dot-notation require/module re-expose next to eval / Function / spawn"
    fi
    if m "$RX_CHAIN" && m "$RX_EXECSINK"; then
        report CRITICAL "On-chain dead-drop C2 resolver in $f" \
            "Derives its C2 from public ETH RPC / a chain indexer, then execs the reply"
    fi
done

# --- 4. The padding trick, anywhere. ----------------------------------------
# A long whitespace run followed by a large block of code, so the payload sits
# off the right edge of the editor. Signature- and filename-independent, so it
# still fires on a rotated variant in a renamed file. Minified bundles contain no
# 80-character whitespace runs, so this does not collide with long lines.
# [[:blank:]] not [ ] on the prefilter: the 2026-09 sample indented with TABS,
# which a spaces-only prefilter skips entirely - the awk below already took both.
for f in $(git grep $CACHED -l -a -E "[[:blank:]]{80,}" -- $SCOPE $EXCL 2>/dev/null); do
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
# branch_structure.json joined the .bat pair in the 2026-09 sample - a recon map
# of every branch to force-push the payload onto, git-ignored so it never shows.
for a in temp_auto_push.bat config.bat temp_interactive_push.bat branch_structure.json; do
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
#
# Every editor-config JSON, not just tasks.json: the 2026-09 sample put the real
# autorun task in tasks.json but also planted a decoy one inside settings.json,
# and .code-workspace files take a "tasks" block too.
for t in .vscode/tasks.json .vscode/settings.json .vscode/launch.json \
         .vscode/*.code-workspace *.code-workspace; do
    [ -f "$t" ] || continue

    # An interpreter pointed at a non-code asset is the payload runner, whether
    # or not it is wired to folderOpen (folderOpen only decides how loud it is).
    if grep -qE '(node|deno|bun|npx|python3?)[^"]*\.(woff2?|ttf|otf|ttc|eot|png|jpe?g|gif|ico|dat|bin|svg|map|css)([ "'\'']|$)' "$t" 2>/dev/null; then
        sev=HIGH; grep -q 'folderOpen' "$t" 2>/dev/null && sev=CRITICAL
        report "$sev" "Editor task runs an interpreter against a non-code asset: $t" \
            "node/deno/bun pointed at a disguised payload file"
    fi
    if grep -q 'folderOpen' "$t" 2>/dev/null &&
       grep -qE 'curl|wget|Invoke-WebRequest|iwr |bash -c|powershell -[eE]' "$t" 2>/dev/null; then
        report CRITICAL "Autorun task fetches and executes remote content: $t" ""
    fi
    # The cross-platform node probe - present in every kit tasks.json seen so far.
    if grep -q 'command -v node' "$t" 2>/dev/null && grep -qiE 'where node|>nul' "$t" 2>/dev/null; then
        report CRITICAL "Canned cross-platform node probe from the PolinRider kit: $t" \
            '(command -v node ... || where node ...) - runs the payload on any OS'
    fi
    if grep -q '"label"[[:space:]]*:[[:space:]]*"eslint-check"' "$t" 2>/dev/null &&
       grep -qE 'command -v node|runOn' "$t" 2>/dev/null; then
        report CRITICAL "Canned \"eslint-check\" autorun task from the PolinRider kit: $t" ""
    fi

    case "$t" in
        *settings.json|*.code-workspace)
            if grep -q '"task.allowAutomaticTasks"[[:space:]]*:[[:space:]]*true' "$t" 2>/dev/null; then
                report HIGH "task.allowAutomaticTasks is enabled: $t" \
                    "Removes VS Code's confirmation prompt before folderOpen tasks run"
            fi
            if grep -qE '"tasks"[[:space:]]*:[[:space:]]*[{[]' "$t" 2>/dev/null && grep -q 'runOn' "$t" 2>/dev/null; then
                report HIGH "Decoy \"tasks\" block inside $t" \
                    "Not a valid setting here - cover for the real autorun task next door"
            fi
            if grep -qE '"terminal\.integrated\.hideOnStartup"[[:space:]]*:[[:space:]]*"always"' "$t" 2>/dev/null &&
               grep -qE '"debug\.openDebug"[[:space:]]*:[[:space:]]*"neverOpen"' "$t" 2>/dev/null; then
                report HIGH "Window-hiding settings paired in $t" \
                    "hideOnStartup:always + debug.openDebug:neverOpen - suppresses anything the payload pops"
            fi
            ;;
    esac

    if grep -q "$AWSP" "$t" 2>/dev/null; then
        report HIGH "Actor project-template AWS profile in $t" "$AWSP"
    fi
done

# A FontAwesome weight that does not exist (solid ships 900, regular/light 400),
# or any real-looking font tree living in a repo that has no web front end at all
# (no index.html / public dir / package.json "browser" field). The 2026-09 drop
# used a nonexistent solid weight beside the genuine 400/900 files, in a repo
# with no web front end at all.
for f in $(git ls-files 'public/fonts/*' '**/fonts/fa-*' 'assets/fonts/fa-*' 2>/dev/null); do
    case "$f" in
        *fa-solid-[1-8]00.*|*fa-brands-[1235-9]00.*|*fa-regular-[1235-9]00.*)
            report CRITICAL "Impossible FontAwesome weight: $f" \
                "No such FA weight ships - a payload hiding among the real fa-*-400/900 files"
            ;;
    esac
done
# The kit's tell is a FontAwesome-named font set (fa-brands-*, fa-solid-*, ...)
# under public/fonts in a repo that ships no web front end. A repo that just
# happens to serve its own webfonts will not carry the fa-* naming, so key on
# that rather than on "has a public/ dir".
if git ls-files 'public/fonts/fa-*' '**/public/fonts/fa-*' 2>/dev/null | grep -q . &&
   ! git ls-files 'package.json' 'index.html' 'public/index.html' 'src/index.*' 'next.config.*' 'vite.config.*' 2>/dev/null | grep -q .; then
    report HIGH "FontAwesome font set under public/fonts in a repo with no web front end" \
        "The PolinRider kit's camouflage font tree - the real fa-* files hide one disguised payload"
fi

# --- 8. Known malicious npm packages. --------------------------------------
for p in tailwind-mainanimation tailwind-autoanimation tailwind-animationbased \
         tailwindcss-style-animate tailwindcss-typography-style \
         tailwindcss-style-modify tailwindcss-animate-style; do
    for f in $(git grep $CACHED -l -F -e "\"$p\"" -- $SCOPE 2>/dev/null); do
        report CRITICAL "Malicious npm package declared in $f" "$p"
    done
done

# --- 8b. Commit-history tampering (ADVISORY - does not block). ------------
# How the 2026-09 payload was delivered: a force-push that replaced the repo's
# initial commit with a new root commit carrying the same subject and the same
# author-date, so `git log --oneline` looked untouched. The committer's timezone
# (-0800) did not match the author's (+0200) because the actor cloned the
# timestamp with GIT_AUTHOR_DATE but their machine's offset leaked into %ci.
#
# This is a weak signal on its own - a rebase across a timezone move produces the
# same shape - so it only PRINTS a note, never calls report(), never blocks. The
# real backstop for a force-push is server-side branch protection + the
# polin-guard GitHub Action (see INCIDENT.md). Skipped in staged mode.
if [ "$MODE" != "staged" ] && git rev-parse --verify -q HEAD >/dev/null 2>&1; then
    tzmix=$(git log -n 50 --no-merges --format='%h %ae %ce %ai %ci' 2>/dev/null | awk '
        { ae=$2; ce=$3; atz=$6; ctz=$9;
          if (ae==ce && atz!=ctz) print "        " $1 "  author " atz " vs committer " ctz }' 2>/dev/null)
    if [ -n "$tzmix" ]; then
        printf '  [note] author/committer timezone mismatch on recent commits (not blocking):\n%s\n' "$tzmix"
        printf '         benign after a cross-timezone rebase; suspicious if you did not rebase.\n'
    fi
fi

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
