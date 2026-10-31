"""Compiler analysis for C programs built as Linux ELF executables."""

import tempfile
import time
from pathlib import Path

from . import lab_adapter
from .elf_utils import NotSupportedBinary, load_elf
from .rules import evaluate, source_functions_from_text
from .schemas_compat import Evidence, Finding, ModuleResult

WRAPPER_REL = "wrapper/simulated-compromised-clang"
SIM_PREFIX = "[SIMULATED COMPILER COMPROMISE] "
UNSUPPORTED_EXT = {".cpp", ".cc", ".cxx", ".c++", ".hpp", ".m", ".mm", ".rs", ".go", ".f90"}
ALLOWED_OPT = {"-O0", "-O1", "-O2", "-O3", "-Os"}
CHECKS = ["source_function_expectation", "cross_compiler_context", "import_check", "rodata_string_check"]


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def run(sample_path, options=None):
    options = options or {}
    started = time.time()
    res = ModuleResult(module="compiler", status="ok")

    def finish():
        res.duration_ms = int((time.time() - started) * 1000)
        return res.model_dump(mode="json")

    def fail(code, message, detail=""):
        res.status = "error"
        res.errors.append({"code": code, "message": message, "detail": detail})
        return finish()

    sample = Path(sample_path).resolve()
    src = sample / "src"
    files = sorted(p for p in src.iterdir() if p.is_file()) if src.is_dir() else []
    bad = [p.name for p in files if p.suffix.lower() in UNSUPPORTED_EXT]
    if bad:
        return fail("INVALID_INPUT", "The MVP supports C sources only. Unsupported files: " + ", ".join(bad))
    c_files = [p for p in files if p.suffix == ".c"]
    if not c_files:
        return fail("INVALID_INPUT", f"No .c files found in {src}")
    opt = options.get("opt_level", "-O0")
    if opt not in ALLOWED_OPT:
        return fail("INVALID_INPUT", f"Unsupported optimisation flag {opt}")
    strip = bool(options.get("strip", False))

    wrapper = sample / WRAPPER_REL
    project_cc = options.get("project_cc")
    simulated = False
    if project_cc is None:
        if wrapper.exists() and options.get("use_wrapper", True):
            project_cc, simulated = f"sh /work/sample/{WRAPPER_REL}", True
        else:
            project_cc = "clang"
    elif "simulated-compromised" in project_cc:
        simulated = True

    problem = lab_adapter.check()
    if problem:
        return fail(problem[0], problem[1])
    out_dir = Path(options.get("out_dir") or tempfile.mkdtemp(prefix="bg_compiler_")).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        lab_adapter.run_lab(sample, out_dir, project_cc, opt_level=opt, strip=strip,
                            timeout=options.get("docker_timeout", options.get("timeout", 180)),
                            scan_id=options.get("scan_id", "adhoc"))
    except lab_adapter.LabError as e:
        return fail(e.code, e.message, e.detail)

    try:
        project = load_elf(out_dir / "project" / "app")
        reference = load_elf(out_dir / "reference" / "app")
    except NotSupportedBinary as e:
        return fail("INVALID_INPUT", str(e))
    except Exception as e:
        return fail("PARSE_ERROR", "Could not read compiled binaries", str(e))

    caveats = []
    if opt != "-O0":
        caveats.append("OPTIMISED_BUILD")
    stripped = not (project.has_symtab and reference.has_symtab)
    if stripped:
        caveats.append("STRIPPED_BINARY")
    source_text = "\n".join(_read(p) for p in c_files)[:1_000_000]
    names = {x.strip() for x in _read(out_dir / "source_functions.txt").splitlines() if x.strip()}
    if not names:
        names = source_functions_from_text(source_text)
    if stripped or not names:
        res.status = "partial"
        reason = "Binary has no symbol table (stripped)" if stripped else "No source functions found"
        res.errors.append({"code": "PARSE_ERROR",
                           "message": reason + ". Function-level checks were skipped; imports and strings were still checked",
                           "detail": ""})

    hits = evaluate(project, reference, names, source_text, caveats=caveats)
    for i, hit in enumerate(hits, start=1):
        sim = simulated and hit["build"] == "project"
        res.findings.append(Finding(
            id=f"C-{i:03d}", module="compiler", category="COMPILER_ANOMALY",
            severity=hit["severity_hint"], confidence="MEDIUM",
            subject={"build": hit["build"], "rule": hit["rule_id"], "simulated": sim},
            title=(SIM_PREFIX if sim else "") + hit["title"],
            evidence=[Evidence(type="rule_hit", rule_id=hit["rule_id"],
                               data={**hit["data"], "simulated_compromise": sim},
                               untrusted_text=hit["untrusted"])],
        ))
    res.checks_performed = list(CHECKS)
    if not hits:
        res.findings.append(Finding(
            id="C-001", module="compiler", category="NO_KNOWN_ISSUES", severity="INFO", confidence="LOW",
            subject={"sample": sample.name, "simulated": simulated},
            title="No compiler anomalies detected by the checks performed",
            evidence=[Evidence(type="tool_output", data={"checks": CHECKS, "caveats": caveats,
                                                          "simulated_compromise": simulated})],
        ))
    versions = _read(out_dir / "versions.txt").splitlines()
    res.tool_versions = {
        "clang": versions[0] if versions else "", "gcc": versions[1] if len(versions) > 1 else "",
        "project_compiler": project_cc, "simulated_wrapper": simulated, "artifacts_dir": str(out_dir),
        "analysis_scope": {"language": "C", "format": "Linux ELF", "optimisation": opt,
                           "stripped": stripped, "caveats": caveats},
    }
    res.duration_ms = int((time.time() - started) * 1000)
    return finish()
