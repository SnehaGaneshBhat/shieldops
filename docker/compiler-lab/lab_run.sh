#!/usr/bin/env bash
set -euo pipefail

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

# Safe recursive C source discovery using null-delimited find and Bash array
mapfile -d '' -t FILES < <(find "$SRC" -type f -name "*.c" -print0 | sort -z)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "No .c files found in $SRC" >&2
  exit 1
fi

case "$PROJECT_CC" in
  "sh /work/sample/wrapper/simulated-compromised-clang"|/work/sample/wrapper/simulated-compromised-clang|"sh wrapper/simulated-compromised-clang"|wrapper/simulated-compromised-clang|simulated-compromised-clang)
    echo "NOTE: SIMULATED compiler compromise (team-made wrapper)"
    ;;
esac

mkdir -p "$OUT/project" "$OUT/reference"
$PROJECT_CC $FLAGS -o "$OUT/project/app" "${FILES[@]}"
gcc $FLAGS -o "$OUT/reference/app" "${FILES[@]}"

if [ "$BG_STRIP" = "1" ]; then
  strip "$OUT/project/app" "$OUT/reference/app"
fi

for d in project reference; do
  nm -n "$OUT/$d/app" > "$OUT/$d/nm.txt" 2>/dev/null || true
  nm -D --undefined-only "$OUT/$d/app" > "$OUT/$d/nm_imports.txt" 2>/dev/null || true
  readelf -S -h "$OUT/$d/app" > "$OUT/$d/readelf.txt"
  objdump -d -M intel --no-show-raw-insn "$OUT/$d/app" > "$OUT/$d/disasm.txt"
  sha256sum "$OUT/$d/app" > "$OUT/$d/sha256.txt"
done

ctags -x --kinds-C=f "${FILES[@]}" | awk '{print $1}' | sort -u > "$OUT/source_functions.txt" || true

# Explicit recognition of supported compiler configurations
COMPILER_ID=""
case "$PROJECT_CC" in
  clang|/usr/bin/clang|/usr/local/bin/clang|/bin/clang)
    COMPILER_ID="clang"
    ;;
  gcc|/usr/bin/gcc|/usr/local/bin/gcc|/bin/gcc)
    COMPILER_ID="gcc"
    ;;
  "sh /work/sample/wrapper/simulated-compromised-clang"|/work/sample/wrapper/simulated-compromised-clang|"sh wrapper/simulated-compromised-clang"|wrapper/simulated-compromised-clang|simulated-compromised-clang)
    # Recognize simulated-compromised wrapper configuration explicitly and bypass to trusted real clang
    COMPILER_ID="clang"
    ;;
  *)
    COMPILER_ID=""
    ;;
esac

# Resolve selected trusted compiler using controlled lookup in trusted system directories
RESOLVED_PREP_CC=""
if [ -n "$COMPILER_ID" ]; then
  for dir in /usr/bin /usr/local/bin /bin; do
    candidate="$dir/$COMPILER_ID"
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then
      RESOLVED_PREP_CC="$candidate"
      break
    fi
  done
fi

if [ -z "$RESOLVED_PREP_CC" ]; then
  echo "Compiler selection or resolution cannot be verified for: $PROJECT_CC" > "$OUT/preprocessed.err"
  echo "1" > "$OUT/preprocessed.status"
  : > "$OUT/preprocessed.c"
  : > "$OUT/prep_compiler.txt"
else
  # Record compiler identity and resolved path in preprocessing metadata
  printf "compiler_id=%s\ncompiler_path=%s\n" "$COMPILER_ID" "$RESOLVED_PREP_CC" > "$OUT/prep_compiler.txt"
  # Invoke through verified executable path
  if "$RESOLVED_PREP_CC" -E $FLAGS "${FILES[@]}" > "$OUT/preprocessed.c" 2>"$OUT/preprocessed.err"; then
    echo "0" > "$OUT/preprocessed.status"
  else
    echo "1" > "$OUT/preprocessed.status"
  fi
fi

{ clang --version | head -1; gcc --version | head -1; } > "$OUT/versions.txt"
echo "lab_run complete"
