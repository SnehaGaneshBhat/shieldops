#!/usr/bin/env bash
FAILED=0
pass() { echo PASS $1; }
fail() { echo FAIL $1 - $2; FAILED=1; }
command -v git >/dev/null && pass git || fail git 'install git'
python3.12 -c 'import sys' 2>/dev/null && pass python3.12 || fail python3.12 'install python3.12 and python3.12-venv'
docker info >/dev/null 2>&1 && pass docker || fail docker 'start Docker Desktop and enable WSL integration'
command -v node >/dev/null && node -v | grep -q '^v20' && pass node20 || fail node20 'needed by P4 only'
command -v syft >/dev/null && pass syft || fail syft 'needed by P1 only'
exit $FAILED
