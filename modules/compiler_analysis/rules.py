"""Deterministic source-to-binary comparison rules; this module never runs tools."""

import codecs
import json
import os
import re

HERE = os.path.dirname(__file__)
LIT_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
FUNC_RE = re.compile(r"^[A-Za-z_] [\w\s\*]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", re.M | re.X)
KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof"}
OPT_CAVEAT = "OPTIMISED_BUILD"


def load_allowlist():
    with open(os.path.join(HERE, "allowlist.json"), encoding="utf-8") as stream:
        return json.load(stream)


def sanitize(text, limit=200):
    return "".join(ch for ch in text if ch.isprintable())[:limit]


def source_functions_from_text(text):
    return {name for name in FUNC_RE.findall(text) if name not in KEYWORDS}


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
