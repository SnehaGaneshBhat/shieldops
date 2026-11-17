"""Deterministic source-to-binary comparison rules; this module never runs tools."""

import codecs
import json
import os
import re

HERE = os.path.dirname(__file__)
LIT_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
FUNC_RE = re.compile(r"^[A-Za-z_] [\w\s\*]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", re.M | re.X)
KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof",
    "else", "do", "case", "default", "break", "continue", "goto",
    "typedef", "struct", "union", "enum",
    "extern", "static", "inline", "const", "volatile", "restrict",
    "signed", "unsigned", "void", "char", "short", "int", "long",
    "float", "double", "_Bool", "_Complex", "_Imaginary", "_Static_assert",
    "__attribute__", "__attribute", "__declspec", "__asm__", "__asm",
    "__inline__", "__inline", "__volatile__", "__const__", "__restrict__", "__restrict",
}
_ATTR_NAMES = {"__attribute__", "__attribute", "__declspec", "__asm__", "__asm"}
_CLEAN_RE = re.compile(
    r"""
    /\*[\s\S]*?\*/                             # block comment
    | //.*?$                                   # line comment
    | "(?:[^"\\\n]|\\.)*"                      # string literal
    | '(?:[^'\\]|\\.)*'                        # character literal
    | ^[ \t]*\#[^\r\n]*(?:\\[\r\n][^\r\n]*)*$ # preprocessor directive
    """,
    re.VERBOSE | re.MULTILINE,
)
_TOKEN_RE = re.compile(r"[A-Za-z_]\w*|[();{}*,=\[\]]")
OPT_CAVEAT = "OPTIMISED_BUILD"


def load_allowlist():
    with open(os.path.join(HERE, "allowlist.json"), encoding="utf-8") as stream:
        return json.load(stream)


def sanitize(text, limit=200):
    return "".join(ch for ch in text if ch.isprintable())[:limit]


def source_functions_from_text(text):
    """Extract C function definition names from source text using bounded tokenization."""
    if not text:
        return set()

    def _preserve_newlines(m):
        nl = m.group(0).count("\n")
        return "\n" * nl if nl else " "

    cleaned = _CLEAN_RE.sub(_preserve_newlines, text)
    tokens = _TOKEN_RE.findall(cleaned)
    n = len(tokens)
    i = 0
    funcs = set()
    brace_depth = 0

    while i < n:
        tok = tokens[i]

        if tok == "{":
            brace_depth += 1
            i += 1
            continue
        elif tok == "}":
            if brace_depth > 0:
                brace_depth -= 1
            i += 1
            continue

        # In C, functions can only be defined at top-level scope (brace_depth == 0)
        if brace_depth != 0:
            i += 1
            continue

        # Linkage block: extern "C" { ... }
        if tok == "extern" and i + 1 < n and tokens[i + 1] == "{":
            i += 2
            continue

        # Skip typedef declarations up to terminating semicolon or struct body
        if tok == "typedef":
            while i < n and tokens[i] not in (";", "{"):
                i += 1
            continue

        # Skip struct / union / enum definitions with braces, but do not skip
        # functions returning struct/union/enum types (e.g. struct Foo make_foo(void) { ... })
        if tok in ("struct", "union", "enum"):
            j = i + 1
            has_brace = False
            while j < n and tokens[j] not in (";", "(", ")"):
                if tokens[j] == "{":
                    has_brace = True
                    break
                j += 1
            if has_brace:
                i = j + 1
                b = 1
                while i < n and b > 0:
                    if tokens[i] == "{":
                        b += 1
                    elif tokens[i] == "}":
                        b -= 1
                    i += 1
                continue

        # Skip compiler attributes at top level: e.g. __attribute__((...))
        if tok in _ATTR_NAMES:
            i += 1
            if i < n and tokens[i] == "(":
                i += 1
                p = 1
                while i < n and p > 0:
                    if tokens[i] == "(":
                        p += 1
                    elif tokens[i] == ")":
                        p -= 1
                    i += 1
            continue

        # Function definition pattern:
        # 1. Standard: candidate(...) {
        # 2. Parenthesized name: (candidate)(...) {
        # 3. Function returning function pointer: (*candidate(...))(...) {
        candidate = None
        j = -1
        if tok not in KEYWORDS and re.match(r"^[A-Za-z_]\w*$", tok):
            candidate = tok
            j = i + 1
        elif tok == "(" and i + 2 < n and tokens[i + 2] == ")":
            inner = tokens[i + 1]
            if inner not in KEYWORDS and re.match(r"^[A-Za-z_]\w*$", inner):
                candidate = inner
                j = i + 3
        elif tok == "(" and i + 3 < n and tokens[i + 1] == "*":
            inner = tokens[i + 2]
            if inner not in KEYWORDS and re.match(r"^[A-Za-z_]\w*$", inner):
                k = i + 3
                if k < n and tokens[k] == "(":
                    p = 1
                    k += 1
                    while k < n and p > 0:
                        if tokens[k] == "(":
                            p += 1
                        elif tokens[k] == ")":
                            p -= 1
                        k += 1
                    if k < n and tokens[k] == ")":
                        candidate = inner
                        j = k + 1

        if candidate and 0 <= j < n and tokens[j] == "(":
            # Scan parameter list (...) with balanced parentheses
            p = 1
            j += 1
            while j < n and p > 0:
                if tokens[j] == "(":
                    p += 1
                elif tokens[j] == ")":
                    p -= 1
                j += 1

            # Skip trailing attributes: __attribute__((...))
            while j < n and tokens[j] in _ATTR_NAMES:
                j += 1
                if j < n and tokens[j] == "(":
                    j += 1
                    p = 1
                    while j < n and p > 0:
                        if tokens[j] == "(":
                            p += 1
                        elif tokens[j] == ")":
                            p -= 1
                        j += 1

            # If opening brace immediately follows, this is a function definition
            if j < n and tokens[j] == "{":
                funcs.add(candidate)
                brace_depth = 1
                i = j + 1
                continue

        i += 1

    return funcs


def source_literals(text):
    values = set()
    for raw in LIT_RE.findall(text):
        try:
            values.add(codecs.decode(raw, "unicode_escape").strip())
        except Exception:
            values.add(raw.strip())
    return values


def evaluate(project, reference, source_funcs, source_text, allow=None, caveats=()):
    allow = allow or load_allowlist()
    runtime_funcs = set(allow["runtime_functions"])
    runtime_imports = set(allow["runtime_imports"])
    equivalents = allow["import_equivalents"]
    risky_imports = set(allow["risky_imports"])
    tokens = set(re.findall(r"[A-Za-z_]\w*", source_text))
    literals = source_literals(source_text)
    caveats = list(caveats)
    optimised = OPT_CAVEAT in caveats
    hits = []

    def hit(rule, build, severity, title, data, untrusted=()):
        hits.append({"rule_id": rule, "build": build, "severity_hint": severity, "title": title,
                     "data": {**data, "caveats": caveats}, "untrusted": list(untrusted)})

    for label, info, other in (("project", project, reference), ("reference", reference, project)):
        if source_funcs and info.has_symtab:
            for fn in sorted(info.defined_funcs - source_funcs - runtime_funcs):
                hit("UNEXPECTED_FUNCTION", label, "MEDIUM", f"Function {fn} exists in the {label} build but not in the source",
                    {"function": fn, "present_in_other_build": fn in other.defined_funcs, "basis": "source_expectation"})
            for fn in sorted(source_funcs - info.defined_funcs):
                hit("MISSING_SOURCE_FUNCTION", label, "LOW" if optimised else "MEDIUM",
                    f"Source function {fn} is missing from the {label} build",
                    {"function": fn, "present_in_other_build": fn in other.defined_funcs, "basis": "source_expectation"})
        unexplained = [imp for imp in sorted(info.imports - runtime_imports)
                       if not ((set(equivalents.get(imp, [])) | {imp}) & tokens)]
        if unexplained:
            risky = sorted(set(unexplained) & risky_imports)
            hit("UNEXPECTED_IMPORT", label, "HIGH" if risky else "LOW",
                f"The {label} build imports library functions the source does not use",
                {"imports": unexplained, "risky_imports": risky, "basis": "source_expectation"})
        extra = sorted(value for value in info.rodata_strings if value not in literals)
        if extra:
            hit("UNEXPECTED_STRING", label, "LOW", f"The {label} build contains {len(extra)} string(s) not found in the source",
                {"count": len(extra), "basis": "source_expectation"}, [sanitize(value) for value in extra[:20]])
    return hits
