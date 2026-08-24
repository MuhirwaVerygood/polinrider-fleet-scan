#!/bin/sh
# PolinRider pre-commit gate. Blocks the payload before it reaches history.
DIR=$(cd "$(dirname "$0")" && pwd)
if [ -f "$DIR/pollinrider-scan.sh" ]; then SCAN="$DIR/pollinrider-scan.sh"; else SCAN="$DIR/../pollinrider-scan.sh"; fi
[ -f "$SCAN" ] || { echo "polinrider: scanner missing - commit allowed UNVERIFIED" >&2; exit 0; }
sh "$SCAN" staged || exit 1
