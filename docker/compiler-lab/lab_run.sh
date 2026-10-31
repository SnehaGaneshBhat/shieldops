#!/bin/sh
set -eu
SRC=/work/sample/src
OUT=/out
PROJECT_CC="${PROJECT_CC:-clang}"
BG_OPT="${BG_OPT:--O0}"
BG_STRIP="${BG_STRIP:-0}"
case "$BG_OPT" in
  -O0|-O1|-O2|-O3|-Os) ;;
  *) echo "unsupported BG_OPT: $BG_OPT" >&2; exit 2 ;;
esac
FLAGS="$BG_OPT -g0 -fno-pie -no-pie"
FILES=$(ls "$SRC"/*.c)
case "$PROJECT_CC" in
  *simulated-compromised*) echo "NOTE: SIMULATED compiler compromise (team-made wrapper)" ;;
esac
mkdir -p "$OUT/project" "$OUT/reference"
$PROJECT_CC $FLAGS -o "$OUT/project/app" $FILES
gcc $FLAGS -o "$OUT/reference/app" $FILES
if [ "$BG_STRIP" = "1" ]; then strip "$OUT/project/app" "$OUT/reference/app"; fi
for d in project reference; do
  nm -n "$OUT/$d/app" > "$OUT/$d/nm.txt" 2>/dev/null || true
  nm -D --undefined-only "$OUT/$d/app" > "$OUT/$d/nm_imports.txt" 2>/dev/null || true
  readelf -S -h "$OUT/$d/app" > "$OUT/$d/readelf.txt"
  objdump -d -M intel --no-show-raw-insn "$OUT/$d/app" > "$OUT/$d/disasm.txt"
  sha256sum "$OUT/$d/app" > "$OUT/$d/sha256.txt"
done
ctags -x --kinds-C=f $FILES | awk '{print $1}' | sort -u > "$OUT/source_functions.txt" || true
{ clang --version | head -1; gcc --version | head -1; } > "$OUT/versions.txt"
echo "lab_run complete"
