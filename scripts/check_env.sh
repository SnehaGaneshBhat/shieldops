#!/usr/bin/env bash
FAILED=0
pass() { echo PASS "$@"; }
fail() { echo FAIL "$1" - "$2"; FAILED=1; }
command -v git >/dev/null && pass git || fail git 'install git'
python3.12 -c 'import sys' 2>/dev/null && pass python3.12 || fail python3.12 'install python3.12 and python3.12-venv'
docker info >/dev/null 2>&1 && pass docker || fail docker 'start Docker Desktop and enable WSL integration'

if command -v node >/dev/null 2>&1; then
    NODE_VER=$(node -v 2>/dev/null || true)
    NODE_MAJOR=$(echo "$NODE_VER" | sed -E 's/^v([0-9]+).*/\1/')
    if [[ "$NODE_MAJOR" =~ ^[0-9]+$ ]] && [ "$NODE_MAJOR" -ge 20 ]; then
        pass "node (v$NODE_MAJOR)"
    else
        fail node "found ${NODE_VER:-unknown}; Node.js 20 or later required (needed by P4 only)"
    fi
else
    fail node 'install Node.js 20 or later (needed by P4 only)'
fi

command -v syft >/dev/null && pass syft || fail syft 'needed by P1 only'
exit $FAILED
