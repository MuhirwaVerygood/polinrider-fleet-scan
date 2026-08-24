#!/bin/sh
# PolinRider pre-push gate. Backstop for anything committed before the
# pre-commit hook existed, or waved through with --no-verify.
DIR=$(cd "$(dirname "$0")" && pwd)
if [ -f "$DIR/pollinrider-scan.sh" ]; then SCAN="$DIR/pollinrider-scan.sh"; else SCAN="$DIR/../pollinrider-scan.sh"; fi
[ -f "$SCAN" ] || { echo "polinrider: scanner missing - push allowed UNVERIFIED" >&2; exit 0; }
sh "$SCAN" tree || exit 1
