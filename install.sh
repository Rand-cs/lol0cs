#!/usr/bin/env bash
# install.sh — LOL0CS setup script
# author: LOUAA AL MITHEAB

set -e

TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_BIN="$TOOL_DIR/lol0cs"

echo "[*] LOL0CS installer"
echo "    root: $TOOL_DIR"
echo


PY=$(command -v python3 2>/dev/null || true)
if [ -z "$PY" ]; then
    echo "[!] python3 not found in PATH"
    exit 1
fi

PY_VER=$("$PY" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJ=$(echo "$PY_VER" | cut -d. -f1)
PY_MIN=$(echo "$PY_VER" | cut -d. -f2)
if [ "$PY_MAJ" -lt 3 ] || { [ "$PY_MAJ" -eq 3 ] && [ "$PY_MIN" -lt 11 ]; }; then
    echo "[!] Python 3.11+ required (found $PY_VER)"
    exit 1
fi
echo "[+] Python $PY_VER"

chmod +x "$TOOL_BIN"
echo "[+] $TOOL_BIN marked executable"


"$PY" "$TOOL_BIN" init
echo "[+] integrity manifest generated"


if [ "${1:-}" = "--link" ]; then
    LINK_PATH="/usr/local/bin/lol0cs"
    if ln -sf "$TOOL_BIN" "$LINK_PATH" 2>/dev/null; then
        echo "[+] symlinked to $LINK_PATH"
    else
        echo "[!] could not write to /usr/local/bin — try: sudo ./install.sh --link"
    fi
fi

echo
echo "[+] done. run: ./lol0cs help"
