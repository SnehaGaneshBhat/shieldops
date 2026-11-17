"""Compiler analysis for C programs built as Linux ELF executables."""

import re
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
TRUSTED_COMPILER_DIRS = {Path("/usr/bin"), Path("/usr/local/bin"), Path("/bin")}
TRUSTED_COMPILER_IDS = {"clang", "gcc"}
SUPPORTED_SIMULATED_WRAPPERS = {
    f"sh /work/sample/{WRAPPER_REL}",
    f"/work/sample/{WRAPPER_REL}",
    f"sh {WRAPPER_REL}",
    WRAPPER_REL,
    "simulated-compromised-clang",
}


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _parse_prep_compiler_metadata(text):
    """Parse prep_compiler.txt into (compiler_id, compiler_path)."""
    if not text:
        return "", ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    metadata = {}
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            metadata[k.strip()] = v.strip()
    if "compiler_id" in metadata or "compiler_path" in metadata:
        return metadata.get("compiler_id", ""), metadata.get("compiler_path", "")
    if lines:
        cid = lines[0]
        cpath = lines[1] if len(lines) > 1 else ""
        return cid, cpath
    return "", ""


def _validate_prep_compiler(cid, cpath):
    """Validate compiler ID and executable path against trusted constraints.

    Returns (is_valid, reason).
    """
    if not cid:
        return False, "compiler metadata missing or unverified (none)"
    if cid not in TRUSTED_COMPILER_IDS:
        return False, f"compiler metadata missing or unverified ({cid})"
    if not cpath:
        return False, "compiler executable path missing or empty"

    try:
        p = Path(cpath)
        if not p.is_absolute():
            return False, f"compiler executable path cannot be verified ({cpath})"
        if p.name != cid:
            return False, f"compiler executable path cannot be verified ({cpath})"
        if p.parent not in TRUSTED_COMPILER_DIRS:
            return False, f"compiler executable path cannot be verified ({cpath})"
    except Exception:
        return False, f"compiler executable path cannot be verified ({cpath})"

    return True, ""


def _resolve_project_rel_path(raw_path, sample, project_rel_paths):
    """Resolve raw_path from a preprocessor linemarker to a normalized project-relative path.

    Returns the normalized relative path string if raw_path belongs to project_rel_paths,
    or None if it is a system header, built-in, or third-party/unrelated path.
    """
    if not raw_path or (raw_path.startswith("<") and raw_path.endswith(">")):
        return None

    norm_path = raw_path.replace("\\", "/")

    # Check container mount path: /work/sample/<rel_path>
    if norm_path.startswith("/work/sample/"):
        rel = norm_path[len("/work/sample/"):].lstrip("/")
        clean_rel = Path(rel).as_posix()
        return clean_rel if clean_rel in project_rel_paths else None

    # Check absolute path on host
    try:
        p = Path(raw_path)
        if p.is_absolute():
            resolved = p.resolve()
            if resolved.is_relative_to(sample):
                rel = resolved.relative_to(sample).as_posix()
                return rel if rel in project_rel_paths else None
    except (ValueError, OSError):
        pass

    # Check relative path
    clean_rel = Path(raw_path).as_posix()
    if clean_rel.startswith("./"):
        clean_rel = clean_rel[2:]
    if clean_rel in project_rel_paths:
        return clean_rel
    candidates = [p for p in project_rel_paths if p == clean_rel or p.endswith("/" + clean_rel)]
    if len(candidates) == 1:
        return candidates[0]

    return None


def _is_project_file(raw_path, sample, project_rel_paths):
    """Determine whether raw_path from a linemarker refers to a project source or header file."""
    return _resolve_project_rel_path(raw_path, sample, project_rel_paths) is not None


def _filter_preprocessed(prep_text, sample, project_rel_paths):
    """Keep only lines that originate from project C source/header files according to linemarkers.

    Returns (filtered_text, seen_c_rel_paths).
    """
    source_lines = []
    is_source = False
    seen_c_rel_paths = set()

    for line in prep_text.splitlines():
        m = re.match(r'^#\s+\d+\s+"([^"]+)"(?:\s+([1234\s]*))?', line)
        if m:
            raw_path = m.group(1)
            flags = (m.group(2) or "").split()
            # Flag 3 explicitly marks system headers in GCC/Clang
            if "3" in flags:
                is_source = False
            else:
                rel = _resolve_project_rel_path(raw_path, sample, project_rel_paths)
                if rel is not None:
                    is_source = True
                    if rel.endswith(".c"):
                        seen_c_rel_paths.add(rel)
                else:
                    is_source = False
        elif is_source:
            source_lines.append(line)

    return "\n".join(source_lines), seen_c_rel_paths


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
    all_src_files = sorted(p for p in src.rglob("*") if p.is_file()) if src.is_dir() else []
    bad = [p.name for p in all_src_files if p.suffix.lower() in UNSUPPORTED_EXT]
    if bad:
        return fail("INVALID_INPUT", "The MVP supports C sources only. Unsupported files: " + ", ".join(bad))
    c_files = [p for p in all_src_files if p.suffix == ".c"]
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
    elif project_cc in SUPPORTED_SIMULATED_WRAPPERS:
        simulated = True

    problem = lab_adapter.check()
    if problem:
        return fail(problem[0], problem[1])
    out_dir = Path(options.get("out_dir") or tempfile.mkdtemp(prefix="bg_compiler_")).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        out_dir.chmod(0o777)
    except OSError:
        pass
    try:
        lab_adapter.run_lab(sample, out_dir, project_cc, opt_level=opt, strip=strip,
                            timeout=options.get("timeout", 180))
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
    header_files = sorted(p for p in sample.rglob("*.h") if p.is_file())
    project_files = set(c_files) | set(header_files)
    project_rel_paths = {p.relative_to(sample).as_posix() for p in project_files}
    expected_c_rel_paths = {p.relative_to(sample).as_posix() for p in c_files}

    source_text = "\n".join(_read(p) for p in c_files)[:1_000_000]

    prep_file = out_dir / "preprocessed.c"
    prep_err_file = out_dir / "preprocessed.err"
    status_file = out_dir / "preprocessed.status"
    prep_compiler_file = out_dir / "prep_compiler.txt"

    has_prep_artifacts = prep_file.exists() or prep_err_file.exists() or status_file.exists() or prep_compiler_file.exists()
    prep_failed = False
    prep_fail_reason = ""
    source_extraction_available = False

    if has_prep_artifacts:
        prep_err_detail = _read(prep_err_file).strip() if prep_err_file.exists() else ""

        # 1. Require verified compiler metadata
        if not prep_compiler_file.exists():
            prep_failed = True
            prep_fail_reason = "compiler metadata missing"
        else:
            cid, cpath = _parse_prep_compiler_metadata(_read(prep_compiler_file))
            valid, reason = _validate_prep_compiler(cid, cpath)
            if not valid:
                prep_failed = True
                prep_fail_reason = reason

        # 2. Check exit status and error logs
        if not prep_failed:
            if not status_file.exists():
                prep_failed = True
                prep_fail_reason = "preprocessor status metadata missing"
            elif _read(status_file).strip() != "0":
                prep_failed = True
                prep_fail_reason = "preprocessor exited unsuccessfully"
            elif prep_err_detail and "error:" in prep_err_detail.lower():
                prep_failed = True
                prep_fail_reason = "preprocessor reported fatal errors"

        # 3. Check output presence and content
        if not prep_failed:
            prep_content = _read(prep_file) if prep_file.exists() else ""
            if not prep_content.strip():
                prep_failed = True
                prep_fail_reason = "preprocessing output is empty"

        # 4. Filter and verify completeness of expected project translation units in linemarkers
        if not prep_failed:
            filtered_prep, seen_c_rel_paths = _filter_preprocessed(prep_content, sample, project_rel_paths)
            missing_c_files = expected_c_rel_paths - seen_c_rel_paths
            if missing_c_files:
                prep_failed = True
                prep_fail_reason = f"preprocessing output is incomplete (missing translation units: {', '.join(sorted(missing_c_files))})"
            elif not filtered_prep.strip():
                prep_failed = True
                prep_fail_reason = "preprocessed output contains no project source statements"

        if prep_failed:
            res.status = "partial"
            res.errors.append({
                "code": "PARSE_ERROR",
                "message": f"C preprocessing failed or incomplete ({prep_fail_reason}). Function-level checks were skipped; imports and strings were still checked",
                "detail": prep_err_detail[:500],
            })
            names = set()
            source_extraction_available = False
        else:
            # Preprocessing succeeded and verified: preprocessed source is authoritative!
            names = source_functions_from_text(filtered_prep)
            source_extraction_available = True
    else:
        # Preprocessing genuinely unavailable (offline fallback)
        res.status = "partial"
        res.errors.append({
            "code": "PARSE_ERROR",
            "message": "Preprocessed source unavailable (offline fallback). Using raw source extraction; function-level analysis is partial",
            "detail": "",
        })
        ctags_names = {x.strip() for x in _read(out_dir / "source_functions.txt").splitlines() if x.strip()}
        fallback_names = source_functions_from_text(source_text)
        names = ctags_names | fallback_names
        source_extraction_available = True

    checks_performed = []
    skipped_checks = {}

    if stripped:
        if not any(e["message"].startswith("Binary has no symbol table") for e in res.errors):
            res.status = "partial"
            res.errors.append({
                "code": "PARSE_ERROR",
                "message": "Binary has no symbol table (stripped). Function-level checks were skipped; imports and strings were still checked",
                "detail": "",
            })

    if source_extraction_available and names and not stripped:
        checks_performed.extend(["source_function_expectation", "cross_compiler_context"])
    else:
        if stripped:
            reason = "Binary has no symbol table (stripped)"
        elif not source_extraction_available:
            reason = f"Source function extraction unavailable ({prep_fail_reason or 'preprocessor failed'})"
        elif not names:
            reason = "No source function definitions found in parsed source"
            if not any(e["message"].startswith("No source functions found") for e in res.errors):
                res.status = "partial"
                res.errors.append({
                    "code": "PARSE_ERROR",
                    "message": "No source functions found. Function-level checks were skipped; imports and strings were still checked",
                    "detail": "",
                })
        else:
            reason = "Function-level checks skipped"
        skipped_checks["source_function_expectation"] = reason
        skipped_checks["cross_compiler_context"] = reason

    checks_performed.extend(["import_check", "rodata_string_check"])
    res.checks_performed = checks_performed

    hits = evaluate(project, reference, names, source_text, caveats=caveats)
    for i, hit in enumerate(hits, start=1):
        sim = simulated and hit["build"] == "project"
        res.findings.append(Finding(
            id=f"C-{i:03d}", module="compiler", category="COMPILER_ANOMALY",
            severity=hit["severity_hint"], confidence="MEDIUM",
            subject={"build": hit["build"], "rule": hit["rule_id"], "simulated": sim,
                     "sample": sample.name, "target": str(sample)},
            title=(SIM_PREFIX if sim else "") + hit["title"],
            evidence=[Evidence(type="rule_hit", rule_id=hit["rule_id"],
                               data={**hit["data"], "simulated_compromise": sim},
                               untrusted_text=hit["untrusted"])],
        ))
    if not hits:
        if res.status == "ok":
            res.findings.append(Finding(
                id="C-001", module="compiler", category="NO_KNOWN_ISSUES", severity="INFO", confidence="LOW",
                subject={"sample": sample.name, "target": str(sample), "simulated": simulated},
                title="No compiler anomalies detected by the checks performed",
                evidence=[Evidence(type="tool_output", data={"checks": checks_performed, "skipped_checks": skipped_checks,
                                                              "caveats": caveats, "simulated_compromise": simulated,
                                                              "target": str(sample)})],
            ))
        elif res.status == "partial":
            res.findings.append(Finding(
                id="C-001", module="compiler", category="UNRESOLVED", severity="INFO", confidence="LOW",
                subject={"sample": sample.name, "target": str(sample), "simulated": simulated},
                title=f"No compiler anomalies detected by the subset of checks performed ({', '.join(checks_performed)})",
                evidence=[Evidence(type="tool_output", data={"checks_performed": checks_performed, "skipped_checks": skipped_checks,
                                                              "caveats": caveats, "simulated_compromise": simulated,
                                                              "target": str(sample)})],
            ))
    versions = _read(out_dir / "versions.txt").splitlines()
    res.tool_versions = {
        "clang": versions[0] if versions else "", "gcc": versions[1] if len(versions) > 1 else "",
        "project_compiler": project_cc, "simulated_wrapper": simulated, "artifacts_dir": str(out_dir),
        "target": str(sample),
        "analysis_scope": {"language": "C", "format": "Linux ELF", "optimisation": opt,
                           "stripped": stripped, "caveats": caveats, "skipped_checks": skipped_checks},
    }
    res.duration_ms = int((time.time() - started) * 1000)
    return finish()
