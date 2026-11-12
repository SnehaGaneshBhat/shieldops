from pathlib import Path

import pytest

from modules.compiler_analysis import lab_adapter, run
from modules.compiler_analysis.elf_utils import ElfInfo, NotSupportedBinary, _clean, load_elf
from modules.compiler_analysis.rules import evaluate

SRC = 'int add(int a, int b) { return a + b; }\nint main(void) { printf("hi"); return add(1, 2); }\n'
FUNCS = {"add", "main"}
RT = {"_start", "_init", "_fini"}


def info(funcs, imports=("printf",), strings=("hi",), symtab=True):
    return ElfInfo(path="x", defined_funcs=set(funcs), imports=set(imports),
                   rodata_strings=set(strings), has_symtab=symtab)


def test_optimiser_suffixes_are_normalised():
    assert _clean("main.cold") == "main"
    assert _clean("add.constprop.0") == "add"
    assert _clean("foo.isra.0.cold") == "foo"
    assert _clean("printf@GLIBC_2.2.5") == "printf"


def test_optimised_build_lowers_missing_function_to_low():
    a, b = info({"main"} | RT), info(FUNCS | RT)
    hits = evaluate(a, b, FUNCS, SRC, caveats=["OPTIMISED_BUILD"])
    hit = [item for item in hits if item["rule_id"] == "MISSING_SOURCE_FUNCTION" and item["build"] == "project"][0]
    assert hit["severity_hint"] == "LOW"
    assert "OPTIMISED_BUILD" in hit["data"]["caveats"]


def test_stripped_build_skips_function_rules_but_still_checks_strings():
    a, b = info(set(), symtab=False), info(set(), symtab=False)
    assert evaluate(a, b, FUNCS, SRC) == []
    a2 = info(set(), strings=("hi", "BEACON"), symtab=False)
    hits = evaluate(a2, b, FUNCS, SRC)
    found = {(item["rule_id"], item["build"]) for item in hits}
    assert ("UNEXPECTED_STRING", "project") in found
    assert not any(rule in ("UNEXPECTED_FUNCTION", "MISSING_SOURCE_FUNCTION") for rule, _ in found)


def test_non_elf_output_is_rejected(tmp_path):
    binary = tmp_path / "app"
    binary.write_bytes(b"MZ this is not an ELF file")
    with pytest.raises(NotSupportedBinary):
        load_elf(binary)


def test_cpp_sample_is_rejected_before_docker(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.cpp").write_text("int main() { return 0; }")
    result = run(str(tmp_path))
    assert result["status"] == "error"
    assert result["errors"][0]["code"] == "INVALID_INPUT"


def test_docker_unavailable_is_reported_not_raised(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int main(void) { return 0; }")
    monkeypatch.setattr(lab_adapter, "check", lambda: ("DOCKER_UNAVAILABLE", "Docker is not running"))
    result = run(str(tmp_path))
    assert result["status"] == "error"
    assert result["errors"][0]["code"] == "DOCKER_UNAVAILABLE"


def test_partial_ctags_output_recovers_omitted_functions(tmp_path, monkeypatch):
    """When preprocessing is unavailable, offline fallback combines ctags with source extraction."""
    (tmp_path / "src").mkdir()
    c_code = "int helper(void) { return 1; }\nint main(void) { return helper(); }\n"
    (tmp_path / "src" / "sample.c").write_text(c_code)

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    # ctags has "main", but omits "helper"
    (out_dir / "source_functions.txt").write_text("main\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    dummy_elf = ElfInfo(
        path="x",
        defined_funcs={"main", "helper", "_start"},
        imports=set(),
        rodata_strings=set(),
        has_symtab=True,
    )
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})

    unexpected_funcs = [
        e["data"]["function"]
        for f in result["findings"]
        for e in f.get("evidence", [])
        if e.get("rule_id") == "UNEXPECTED_FUNCTION"
    ]
    assert unexpected_funcs == []
    assert result["status"] == "partial"
    assert any("Preprocessed source unavailable (offline fallback)" in e["message"] for e in result["errors"])


def test_empty_ctags_output_uses_fallback_extraction(tmp_path, monkeypatch):
    """When preprocessing is unavailable and ctags is empty, fallback extraction identifies functions."""
    (tmp_path / "src").mkdir()
    c_code = "int helper(void) { return 1; }\nint main(void) { return helper(); }\n"
    (tmp_path / "src" / "sample.c").write_text(c_code)

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "source_functions.txt").write_text("")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    dummy_elf = ElfInfo(
        path="x",
        defined_funcs={"main", "helper", "_start"},
        imports=set(),
        rodata_strings=set(),
        has_symtab=True,
    )
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "partial"
    unexpected_funcs = [
        e["data"]["function"]
        for f in result["findings"]
        for e in f.get("evidence", [])
        if e.get("rule_id") == "UNEXPECTED_FUNCTION"
    ]
    assert unexpected_funcs == []


def test_if_zero_definitions_excluded_via_preprocessed_source(tmp_path, monkeypatch):
    """Functions defined inside inactive preprocessor branches are excluded from authoritative expectations."""
    (tmp_path / "src").mkdir()
    raw_code = (
        "#if 0\n"
        "int dead_code(void) { return 0; }\n"
        "#endif\n"
        "int active_func(void) { return 42; }\n"
    )
    (tmp_path / "src" / "sample.c").write_text(raw_code)

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "source_functions.txt").write_text("dead_code\nactive_func\n")
    prep_code = (
        '# 1 "/work/sample/src/sample.c"\n'
        'int active_func(void) { return 42; }\n'
    )
    (out_dir / "preprocessed.c").write_text(prep_code)
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    dummy_elf = ElfInfo(
        path="x",
        defined_funcs={"active_func", "_start"},
        imports=set(),
        rodata_strings=set(),
        has_symtab=True,
    )
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "ok"
    missing_funcs = [
        e["data"]["function"]
        for f in result["findings"]
        for e in f.get("evidence", [])
        if e.get("rule_id") == "MISSING_SOURCE_FUNCTION"
    ]
    assert "dead_code" not in missing_funcs
    assert missing_funcs == []


def test_same_function_name_as_active_variable_does_not_leak(tmp_path, monkeypatch):
    """An inactive function name appearing as an active variable token is not mistakenly extracted."""
    (tmp_path / "src").mkdir()
    raw_code = (
        "#if 0\n"
        "int shadow_fn(void) { return 0; }\n"
        "#endif\n"
        "int active_fn(void) {\n"
        "    int shadow_fn = 100;\n"
        "    return shadow_fn;\n"
        "}\n"
    )
    (tmp_path / "src" / "sample.c").write_text(raw_code)

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "source_functions.txt").write_text("shadow_fn\nactive_fn\n")
    prep_code = (
        '# 1 "/work/sample/src/sample.c"\n'
        'int active_fn(void) {\n'
        '    int shadow_fn = 100;\n'
        '    return shadow_fn;\n'
        '}\n'
    )
    (out_dir / "preprocessed.c").write_text(prep_code)
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    dummy_elf = ElfInfo(
        path="x",
        defined_funcs={"active_fn", "_start"},
        imports=set(),
        rodata_strings=set(),
        has_symtab=True,
    )
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "ok"
    missing_funcs = [
        e["data"]["function"]
        for f in result["findings"]
        for e in f.get("evidence", [])
        if e.get("rule_id") == "MISSING_SOURCE_FUNCTION"
    ]
    assert "shadow_fn" not in missing_funcs
    assert missing_funcs == []


def test_predefined_macro_differences_clang_vs_gcc(tmp_path, monkeypatch):
    """Compiler-specific preprocessor branches (__clang__ vs __GNUC__) are correctly expanded by the matching compiler."""
    (tmp_path / "src").mkdir()
    c_code = (
        "#ifdef __clang__\n"
        "int clang_only(void) { return 1; }\n"
        "#endif\n"
        "#if defined(__GNUC__) && !defined(__clang__)\n"
        "int gcc_only(void) { return 2; }\n"
        "#endif\n"
        "int common(void) { return 0; }\n"
    )
    (tmp_path / "src" / "sample.c").write_text(c_code)

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    prep_code = (
        '# 1 "/work/sample/src/sample.c"\n'
        'int clang_only(void) { return 1; }\n'
        'int common(void) { return 0; }\n'
    )
    (out_dir / "preprocessed.c").write_text(prep_code)
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    dummy_elf = ElfInfo(
        path="x",
        defined_funcs={"clang_only", "common", "_start"},
        imports=set(),
        rodata_strings=set(),
        has_symtab=True,
    )
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir), "project_cc": "clang"})
    assert result["status"] == "ok"
    missing = [e["data"]["function"] for f in result["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "MISSING_SOURCE_FUNCTION"]
    unexpected = [e["data"]["function"] for f in result["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "UNEXPECTED_FUNCTION"]
    assert missing == []
    assert unexpected == []


def test_multiple_source_files_and_headers_resolved_paths(tmp_path, monkeypatch):
    """Resolved path filtering includes all project units and headers while excluding external headers with matching basenames."""
    (tmp_path / "src").mkdir()
    (tmp_path / "include").mkdir()
    (tmp_path / "src" / "main.c").write_text("int main(void) { return 0; }\n")
    (tmp_path / "src" / "util.c").write_text("int util_calc(void) { return 10; }\n")
    (tmp_path / "include" / "string.h").write_text("static inline int local_str(void) { return 1; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    prep_code = (
        '# 1 "/work/sample/src/main.c"\n'
        '# 1 "/work/sample/include/string.h" 1\n'
        'static inline int local_str(void) { return 1; }\n'
        '# 2 "/work/sample/src/main.c" 2\n'
        '# 1 "/usr/include/string.h" 1 3 4\n'
        'static inline int sys_string_fn(void) { return 0; }\n'
        '# 3 "/work/sample/src/main.c" 2\n'
        'int main(void) { return local_str(); }\n'
        '# 1 "/work/sample/src/util.c"\n'
        'int util_calc(void) { return 10; }\n'
    )
    (out_dir / "preprocessed.c").write_text(prep_code)
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    dummy_elf = ElfInfo(
        path="x",
        defined_funcs={"main", "util_calc", "local_str", "_start"},
        imports=set(),
        rodata_strings=set(),
        has_symtab=True,
    )
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "ok"
    unexpected = [e["data"]["function"] for f in result["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "UNEXPECTED_FUNCTION"]
    missing = [e["data"]["function"] for f in result["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "MISSING_SOURCE_FUNCTION"]
    assert unexpected == []
    assert missing == []


def test_project_header_inline_functions_and_macro_expansion(tmp_path, monkeypatch):
    """Functions declared via macros and inline functions in project headers are recognized."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "helpers.h").write_text("static inline int inline_helper(void) { return 42; }\n")
    (tmp_path / "src" / "main.c").write_text("#include \"helpers.h\"\nint main(void) { return inline_helper(); }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    prep_code = (
        '# 1 "/work/sample/src/main.c"\n'
        '# 1 "/work/sample/src/helpers.h" 1\n'
        'static inline int inline_helper(void) { return 42; }\n'
        '# 2 "/work/sample/src/main.c" 2\n'
        'void macro_expanded_fn(void) { return; }\n'
        'int main(void) { return inline_helper(); }\n'
    )
    (out_dir / "preprocessed.c").write_text(prep_code)
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    dummy_elf = ElfInfo(
        path="x",
        defined_funcs={"inline_helper", "macro_expanded_fn", "main", "_start"},
        imports=set(),
        rodata_strings=set(),
        has_symtab=True,
    )
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "ok"
    unexpected = [e["data"]["function"] for f in result["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "UNEXPECTED_FUNCTION"]
    assert unexpected == []


def test_preprocessor_failure_reports_partial_status(tmp_path, monkeypatch):
    """When C preprocessing fails, status is reported as partial with PARSE_ERROR and functions are skipped."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int broken(void) { return 1; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "source_functions.txt").write_text("broken\n")
    (out_dir / "preprocessed.c").write_text("")
    (out_dir / "preprocessed.err").write_text("sample.c:1:1: fatal error: missing_header.h: No such file or directory\n")
    (out_dir / "preprocessed.status").write_text("1\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    dummy_elf = ElfInfo(
        path="x",
        defined_funcs={"broken", "_start"},
        imports=set(),
        rodata_strings=set(),
        has_symtab=True,
    )
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "partial"
    assert any(e["code"] == "PARSE_ERROR" and "preprocessing failed" in e["message"].lower() for e in result["errors"])
    func_findings = [
        f for f in result["findings"]
        for e in f.get("evidence", [])
        if e.get("rule_id") in ("UNEXPECTED_FUNCTION", "MISSING_SOURCE_FUNCTION")
    ]
    assert func_findings == []


def test_empty_or_incomplete_preprocessing_output_reports_partial(tmp_path, monkeypatch):
    """Empty or truncated preprocessor output missing expected C translation units is rejected as partial."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "file1.c").write_text("int f1(void) { return 1; }\n")
    (tmp_path / "src" / "file2.c").write_text("int f2(void) { return 2; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    # file2.c is missing from linemarkers (truncated stream)
    prep_code = (
        '# 1 "/work/sample/src/file1.c"\n'
        'int f1(void) { return 1; }\n'
    )
    (out_dir / "preprocessed.c").write_text(prep_code)
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    dummy_elf = ElfInfo(
        path="x",
        defined_funcs={"f1", "f2", "_start"},
        imports=set(),
        rodata_strings=set(),
        has_symtab=True,
    )
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "partial"
    assert any("incomplete" in e["message"].lower() for e in result["errors"])
    func_findings = [
        f for f in result["findings"]
        for e in f.get("evidence", [])
        if e.get("rule_id") in ("UNEXPECTED_FUNCTION", "MISSING_SOURCE_FUNCTION")
    ]
    assert func_findings == []


# -------------------------------------------------------------------------
# Focused Regression Tests for Preprocessing Hardening and Partial Results
# -------------------------------------------------------------------------

def test_compiler_command_substring_spoofing_rejected(tmp_path, monkeypatch):
    """Test 1: Substring spoofing in PROJECT_CC or prep_compiler is rejected as unverified."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint main(void) { return 0; }\n')
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    # Substring contains "clang" but is an unverified compiler configuration
    (out_dir / "prep_compiler.txt").write_text("compiler_id=evil_clang_wrapper\ncompiler_path=/usr/local/bin/evil_clang_wrapper\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir), "project_cc": "evil_clang_wrapper"})
    assert result["status"] == "partial"
    assert any("compiler metadata missing or unverified" in e["message"] for e in result["errors"])
    assert "source_function_expectation" not in result["checks_performed"]
    assert "cross_compiler_context" not in result["checks_performed"]
    assert "import_check" in result["checks_performed"]
    assert "rodata_string_check" in result["checks_performed"]

    # Also verify lab_run.sh has strict case matching without loose *clang* or *gcc* substring patterns
    lab_script = Path("docker/compiler-lab/lab_run.sh").read_text()
    assert "*clang*" not in lab_script
    assert "*gcc*" not in lab_script
    assert "clang|/usr/bin/clang|/usr/local/bin/clang|/bin/clang)" in lab_script


def test_trusted_compiler_resolution_and_invocation_consistency(tmp_path, monkeypatch):
    """Test 2: Preprocessing accepts verified compiler path, rejects unverified or tampered paths."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint main(void) { return 0; }\n')
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    # 1. Tampered / unverified compiler executable path
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/tmp/untrusted/hijacked_clang_exec\n")
    res_tampered = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res_tampered["status"] == "partial"
    assert any("compiler executable path cannot be verified (/tmp/untrusted/hijacked_clang_exec)" in e["message"] for e in res_tampered["errors"])

    # 2. Consistent verified compiler executable path
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    res_verified = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res_verified["status"] == "ok"
    assert "source_function_expectation" in res_verified["checks_performed"]


def test_simulated_wrapper_uses_trusted_compiler_and_detects_injection(tmp_path, monkeypatch):
    """Test 3: Simulated wrapper preprocessing uses trusted compiler, detecting injected backdoor function."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int legitimate_fn(void) { return 1; }\nint main(void) { return legitimate_fn(); }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "source_functions.txt").write_text("legitimate_fn\nmain\n")
    prep_code = (
        '# 1 "/work/sample/src/sample.c"\n'
        'int legitimate_fn(void) { return 1; }\n'
        'int main(void) { return legitimate_fn(); }\n'
    )
    (out_dir / "preprocessed.c").write_text(prep_code)
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    project_elf = ElfInfo(
        path="x",
        defined_funcs={"legitimate_fn", "main", "backdoor_beacon", "_start"},
        imports=set(),
        rodata_strings=set(),
        has_symtab=True,
    )
    ref_elf = ElfInfo(
        path="y",
        defined_funcs={"legitimate_fn", "main", "_start"},
        imports=set(),
        rodata_strings=set(),
        has_symtab=True,
    )

    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: project_elf if "project" in str(p) else ref_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir), "project_cc": "simulated-compromised-clang"})
    assert result["status"] == "ok"
    unexpected = [
        f for f in result["findings"]
        for e in f.get("evidence", [])
        if e.get("rule_id") == "UNEXPECTED_FUNCTION" and e.get("data", {}).get("function") == "backdoor_beacon"
    ]
    assert len(unexpected) == 1
    assert unexpected[0]["title"].startswith("[SIMULATED COMPILER COMPROMISE]")
    assert unexpected[0]["subject"]["simulated"] is True


def test_duplicate_translation_unit_basenames_tracked_separately(tmp_path, monkeypatch):
    """Test 4: Translation units with identical basenames in different directories cannot satisfy each other."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_text("int main(void) { return 0; }\n")
    (tmp_path / "src" / "sub").mkdir()
    (tmp_path / "src" / "sub" / "main.c").write_text("int sub_calc(void) { return 42; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    # 1. Incomplete: only src/main.c is present in linemarkers; src/sub/main.c is missing
    (out_dir / "preprocessed.c").write_text(
        '# 1 "/work/sample/src/main.c"\n'
        'int main(void) { return 0; }\n'
    )
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "sub_calc", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    res_incomplete = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res_incomplete["status"] == "partial"
    assert any("missing translation units: src/sub/main.c" in e["message"] for e in res_incomplete["errors"])

    # 2. Complete: both src/main.c and src/sub/main.c are present in linemarkers
    (out_dir / "preprocessed.c").write_text(
        '# 1 "/work/sample/src/main.c"\n'
        'int main(void) { return 0; }\n'
        '# 1 "/work/sample/src/sub/main.c"\n'
        'int sub_calc(void) { return 42; }\n'
    )
    res_complete = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res_complete["status"] == "ok"
    unexpected = [e["data"]["function"] for f in res_complete["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "UNEXPECTED_FUNCTION"]
    missing = [e["data"]["function"] for f in res_complete["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "MISSING_SOURCE_FUNCTION"]
    assert unexpected == []
    assert missing == []


def test_project_headers_and_static_inline_functions_discoverable(tmp_path, monkeypatch):
    """Test 5: Project headers and static inline definitions are discovered and authoritative."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "helpers.h").write_text("static inline int inline_helper(void) { return 42; }\n")
    (tmp_path / "src" / "main.c").write_text('#include "helpers.h"\nint main(void) { return inline_helper(); }\n')

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    prep_code = (
        '# 1 "/work/sample/src/main.c"\n'
        '# 1 "/work/sample/src/helpers.h" 1\n'
        'static inline int inline_helper(void) { return 42; }\n'
        '# 2 "/work/sample/src/main.c" 2\n'
        'int main(void) { return inline_helper(); }\n'
    )
    (out_dir / "preprocessed.c").write_text(prep_code)
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    dummy_elf = ElfInfo(path="x", defined_funcs={"inline_helper", "main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "ok"
    unexpected = [e["data"]["function"] for f in result["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "UNEXPECTED_FUNCTION"]
    missing = [e["data"]["function"] for f in result["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "MISSING_SOURCE_FUNCTION"]
    assert unexpected == []
    assert missing == []


def test_system_headers_excluded_from_source_expectations(tmp_path, monkeypatch):
    """Test 6: External system headers (flag 3) are excluded from source expectations."""
    (tmp_path / "src").mkdir()
    (tmp_path / "include").mkdir()
    (tmp_path / "src" / "main.c").write_text("int main(void) { return 0; }\n")
    (tmp_path / "include" / "string.h").write_text("static inline int local_str(void) { return 1; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    prep_code = (
        '# 1 "/work/sample/src/main.c"\n'
        '# 1 "/work/sample/include/string.h" 1\n'
        'static inline int local_str(void) { return 1; }\n'
        '# 2 "/work/sample/src/main.c" 2\n'
        '# 1 "/usr/include/string.h" 1 3 4\n'
        'static inline int sys_string_fn(void) { return 0; }\n'
        '# 3 "/work/sample/src/main.c" 2\n'
        'int main(void) { return local_str(); }\n'
    )
    (out_dir / "preprocessed.c").write_text(prep_code)
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    # sys_string_fn is in the ELF (e.g. from glibc), so it should be flagged as UNEXPECTED_FUNCTION
    # because it was excluded from source expectations
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "local_str", "sys_string_fn", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "ok"
    unexpected = [e["data"]["function"] for f in result["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "UNEXPECTED_FUNCTION"]
    assert "sys_string_fn" in unexpected
    assert "local_str" not in unexpected
    assert "main" not in unexpected


def test_missing_or_invalid_compiler_metadata_produces_partial(tmp_path, monkeypatch):
    """Test 7: Missing, empty, or unverifiable compiler metadata yields partial status."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint main(void) { return 0; }\n')
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    # 1. Missing prep_compiler.txt
    res1 = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res1["status"] == "partial"
    assert any("compiler metadata missing" in e["message"] for e in res1["errors"])

    # 2. Empty prep_compiler.txt
    (out_dir / "prep_compiler.txt").write_text("")
    res2 = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res2["status"] == "partial"
    assert any("compiler metadata missing or unverified" in e["message"] for e in res2["errors"])

    # 3. Unsupported / invalid compiler ID
    (out_dir / "prep_compiler.txt").write_text("compiler_id=tcc\ncompiler_path=/usr/bin/tcc\n")
    res3 = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res3["status"] == "partial"
    assert any("compiler metadata missing or unverified (tcc)" in e["message"] for e in res3["errors"])


def test_failed_empty_incomplete_preprocessing_produces_partial(tmp_path, monkeypatch):
    """Test 8: Preprocessing non-zero exit, empty output, or missing translation units produce partial status."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "file1.c").write_text("int f1(void) { return 1; }\n")
    (tmp_path / "src" / "file2.c").write_text("int f2(void) { return 2; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"f1", "f2", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    # 1. Exit status failure
    (out_dir / "preprocessed.c").write_text("")
    (out_dir / "preprocessed.err").write_text("file1.c:1: fatal error: syntax error\n")
    (out_dir / "preprocessed.status").write_text("1\n")
    res_failed = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res_failed["status"] == "partial"
    assert any("preprocessor exited unsuccessfully" in e["message"] for e in res_failed["errors"])

    # 2. Empty output
    (out_dir / "preprocessed.c").write_text("   \n\t\n")
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    res_empty = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res_empty["status"] == "partial"
    assert any("preprocessing output is empty" in e["message"] for e in res_empty["errors"])

    # 3. Incomplete output (file2.c missing from stream)
    (out_dir / "preprocessed.c").write_text('# 1 "/work/sample/src/file1.c"\nint f1(void) { return 1; }\n')
    res_incomplete = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res_incomplete["status"] == "partial"
    assert any("missing translation units: src/file2.c" in e["message"] for e in res_incomplete["errors"])


def test_offline_fallback_remains_partial_with_ctags_supplement(tmp_path, monkeypatch):
    """Test 9: Offline fallback combines ctags with regex fallback, but remains marked partial."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int ctags_fn(void) { return 1; }\nint fallback_fn(void) { return 2; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    # No preprocessing artifacts written
    (out_dir / "source_functions.txt").write_text("ctags_fn\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    dummy_elf = ElfInfo(path="x", defined_funcs={"ctags_fn", "fallback_fn", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "partial"
    assert any("Preprocessed source unavailable (offline fallback)" in e["message"] for e in result["errors"])
    # Both ctags and fallback functions are recognized; no false unexpected/missing findings
    unexpected = [e["data"]["function"] for f in result["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "UNEXPECTED_FUNCTION"]
    missing = [e["data"]["function"] for f in result["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "MISSING_SOURCE_FUNCTION"]
    assert unexpected == []
    assert missing == []


def test_function_level_checks_skipped_when_extraction_unavailable(tmp_path, monkeypatch):
    """Test 10: Function checks are omitted from checks_performed and recorded in skipped_checks on failure."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "preprocessed.c").write_text("")
    (out_dir / "preprocessed.err").write_text("failed")
    (out_dir / "preprocessed.status").write_text("1")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "partial"
    assert "source_function_expectation" not in result["checks_performed"]
    assert "cross_compiler_context" not in result["checks_performed"]
    assert result["checks_performed"] == ["import_check", "rodata_string_check"]

    skipped = result["tool_versions"]["analysis_scope"]["skipped_checks"]
    assert "source_function_expectation" in skipped
    assert "cross_compiler_context" in skipped
    assert "Source function extraction unavailable" in skipped["source_function_expectation"]


def test_import_and_string_checks_run_even_when_function_checks_skipped(tmp_path, monkeypatch):
    """Test 11: Import and string checks run and report findings even when function checks are skipped."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "preprocessed.c").write_text("")
    (out_dir / "preprocessed.err").write_text("failed")
    (out_dir / "preprocessed.status").write_text("1")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    project_elf = ElfInfo(path="x", defined_funcs=set(), imports={"ptrace"}, rodata_strings={"hi", "BACKDOOR_C2"}, has_symtab=False)
    ref_elf = ElfInfo(path="y", defined_funcs=set(), imports=set(), rodata_strings={"hi"}, has_symtab=False)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: project_elf if "project" in str(p) else ref_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "partial"
    rule_ids = {e["rule_id"] for f in result["findings"] for e in f.get("evidence", []) if "rule_id" in e}
    assert "UNEXPECTED_STRING" in rule_ids
    assert "UNEXPECTED_IMPORT" in rule_ids
    assert not ({"UNEXPECTED_FUNCTION", "MISSING_SOURCE_FUNCTION"} & rule_ids)


def test_checks_performed_and_skipped_checks_metadata_reflection(tmp_path, monkeypatch):
    """Test 12: checks_performed accurately reflects executed checks across scan states."""
    (tmp_path / "src").mkdir()

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    # State 1: Complete scan
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")
    out1 = tmp_path / "out1"
    out1.mkdir()
    (out1 / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint main(void) { return 0; }\n')
    (out1 / "preprocessed.err").write_text("")
    (out1 / "preprocessed.status").write_text("0\n")
    (out1 / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out1 / "versions.txt").write_text("clang 17\ngcc 13\n")
    elf_full = ElfInfo(path="x", defined_funcs={"main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: elf_full)

    res1 = run(str(tmp_path), options={"out_dir": str(out1)})
    assert res1["status"] == "ok"
    assert res1["checks_performed"] == ["source_function_expectation", "cross_compiler_context", "import_check", "rodata_string_check"]
    assert res1["tool_versions"]["analysis_scope"]["skipped_checks"] == {}

    # State 2: Stripped binary
    out2 = tmp_path / "out2"
    out2.mkdir()
    (out2 / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint main(void) { return 0; }\n')
    (out2 / "preprocessed.err").write_text("")
    (out2 / "preprocessed.status").write_text("0\n")
    (out2 / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out2 / "versions.txt").write_text("clang 17\ngcc 13\n")
    elf_stripped = ElfInfo(path="x", defined_funcs=set(), imports=set(), rodata_strings=set(), has_symtab=False)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: elf_stripped)

    res2 = run(str(tmp_path), options={"out_dir": str(out2)})
    assert res2["status"] == "partial"
    assert res2["checks_performed"] == ["import_check", "rodata_string_check"]
    assert "Binary has no symbol table (stripped)" in res2["tool_versions"]["analysis_scope"]["skipped_checks"]["source_function_expectation"]

    # State 3: Empty parsed source (source has declarations but no function definitions)
    (tmp_path / "src" / "sample.c").write_text("int g_var = 1;\n")
    out3 = tmp_path / "out3"
    out3.mkdir()
    (out3 / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint g_var = 1;\n')
    (out3 / "preprocessed.err").write_text("")
    (out3 / "preprocessed.status").write_text("0\n")
    (out3 / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out3 / "versions.txt").write_text("clang 17\ngcc 13\n")
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: elf_full)

    res3 = run(str(tmp_path), options={"out_dir": str(out3)})
    assert res3["status"] == "partial"
    assert res3["checks_performed"] == ["import_check", "rodata_string_check"]
    assert "No source function definitions found in parsed source" in res3["tool_versions"]["analysis_scope"]["skipped_checks"]["source_function_expectation"]


def test_partial_results_never_produce_no_known_issues_finding(tmp_path, monkeypatch):
    """Test 13: A partial scan result never emits NO_KNOWN_ISSUES; it emits UNRESOLVED instead."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    # Force partial via offline fallback
    (out_dir / "source_functions.txt").write_text("main\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "partial"
    assert not any(f["category"] == "NO_KNOWN_ISSUES" for f in result["findings"])
    assert len(result["findings"]) == 1
    unresolved_finding = result["findings"][0]
    assert unresolved_finding["category"] == "UNRESOLVED"
    assert "subset of checks performed" in unresolved_finding["title"]


def test_complete_scan_with_no_findings_produces_no_known_issues(tmp_path, monkeypatch):
    """Test 14: A complete scan with zero anomalies emits a single NO_KNOWN_ISSUES finding."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint main(void) { return 0; }\n')
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "ok"
    assert len(result["findings"]) == 1
    clean_finding = result["findings"][0]
    assert clean_finding["category"] == "NO_KNOWN_ISSUES"
    assert clean_finding["title"] == "No compiler anomalies detected by the checks performed"
    assert clean_finding["evidence"][0]["data"]["checks"] == result["checks_performed"]


# -------------------------------------------------------------------------
# Phase 1: Hardened Compiler Validation, Wrapper Recognition, and Discovery
# -------------------------------------------------------------------------

def test_phase1_empty_compiler_path_rejected(tmp_path, monkeypatch):
    """Task 4.1: Reject missing or empty compiler executable path."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint main(void) { return 0; }\n')
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    # Empty compiler_path key value
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=\n")
    res1 = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res1["status"] == "partial"
    assert any("compiler executable path missing or empty" in e["message"] for e in res1["errors"])
    assert "source_function_expectation" not in res1["checks_performed"]

    # Missing compiler_path key entirely
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\n")
    res2 = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res2["status"] == "partial"
    assert any("compiler executable path missing or empty" in e["message"] for e in res2["errors"])


def test_phase1_tmp_untrusted_compiler_path_rejected(tmp_path, monkeypatch):
    """Task 4.2: Reject compiler path under untrusted directories like /tmp/untrusted/clang."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint main(void) { return 0; }\n')
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/tmp/untrusted/clang\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    result = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert result["status"] == "partial"
    assert any("compiler executable path cannot be verified (/tmp/untrusted/clang)" in e["message"] for e in result["errors"])
    assert "source_function_expectation" not in result["checks_performed"]


def test_phase1_compiler_id_path_mismatch_rejected(tmp_path, monkeypatch):
    """Task 4.3: Reject compiler ID and executable path basename mismatch."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint main(void) { return 0; }\n')
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    # clang ID with gcc binary path
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/gcc\n")
    res1 = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res1["status"] == "partial"
    assert any("compiler executable path cannot be verified (/usr/bin/gcc)" in e["message"] for e in res1["errors"])

    # gcc ID with clang binary path
    (out_dir / "prep_compiler.txt").write_text("compiler_id=gcc\ncompiler_path=/usr/bin/clang\n")
    res2 = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res2["status"] == "partial"
    assert any("compiler executable path cannot be verified (/usr/bin/clang)" in e["message"] for e in res2["errors"])


def test_phase1_legitimate_trusted_compiler_paths_accepted(tmp_path, monkeypatch):
    """Task 4.4: Accept approved container paths under /usr/bin, /usr/local/bin, /bin."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint main(void) { return 0; }\n')
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    trusted_configs = [
        ("clang", "/usr/bin/clang"),
        ("clang", "/usr/local/bin/clang"),
        ("gcc", "/bin/gcc"),
        ("gcc", "/usr/bin/gcc"),
    ]
    for cid, cpath in trusted_configs:
        (out_dir / "prep_compiler.txt").write_text(f"compiler_id={cid}\ncompiler_path={cpath}\n")
        res = run(str(tmp_path), options={"out_dir": str(out_dir), "project_cc": cid})
        assert res["status"] == "ok"
        assert "source_function_expectation" in res["checks_performed"]


def test_phase1_exact_simulated_wrapper_recognition(tmp_path, monkeypatch):
    """Task 4.5: Exact recognition of the legitimate simulated-compromised wrapper."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int legitimate_fn(void) { return 1; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "source_functions.txt").write_text("legitimate_fn\n")
    (out_dir / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint legitimate_fn(void) { return 1; }\n')
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)

    project_elf = ElfInfo(path="x", defined_funcs={"legitimate_fn", "backdoor_beacon", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    ref_elf = ElfInfo(path="y", defined_funcs={"legitimate_fn", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: project_elf if "project" in str(p) else ref_elf)

    # Test exact wrapper strings recognized
    for valid_wrapper in ("simulated-compromised-clang", "sh /work/sample/wrapper/simulated-compromised-clang", "wrapper/simulated-compromised-clang"):
        res = run(str(tmp_path), options={"out_dir": str(out_dir), "project_cc": valid_wrapper})
        assert res["status"] == "ok"
        unexp = [f for f in res["findings"] if f.get("category") == "COMPILER_ANOMALY"]
        assert len(unexp) == 1
        assert unexp[0]["title"].startswith("[SIMULATED COMPILER COMPROMISE]")
        assert unexp[0]["subject"]["simulated"] is True


def test_phase1_fake_wrapper_substring_rejected(tmp_path, monkeypatch):
    """Task 4.6: Reject arbitrary strings merely containing simulated-compromised substring."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text("int main(void) { return 0; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "preprocessed.c").write_text('# 1 "/work/sample/src/sample.c"\nint main(void) { return 0; }\n')
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    # Fake wrapper that merely contains the substring
    fake_wrapper = "evil_simulated-compromised_wrapper"
    (out_dir / "prep_compiler.txt").write_text("")
    (out_dir / "preprocessed.status").write_text("1")

    res = run(str(tmp_path), options={"out_dir": str(out_dir), "project_cc": fake_wrapper})
    assert res["status"] == "partial"
    assert not any(f.get("subject", {}).get("simulated") is True for f in res["findings"])
    assert not any("[SIMULATED COMPILER COMPROMISE]" in f["title"] for f in res["findings"])


def test_phase1_recursive_c_source_discovery(tmp_path, monkeypatch):
    """Task 4.7: Discover nested C translation units recursively across multiple directory levels."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text("int main(void) { return 0; }\n")
    (src / "core").mkdir()
    (src / "core" / "engine.c").write_text("int core_engine(void) { return 100; }\n")
    (src / "plugins" / "sub").mkdir(parents=True)
    (src / "plugins" / "sub" / "plugin.c").write_text("int sub_plugin(void) { return 200; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    prep_code = (
        '# 1 "/work/sample/src/main.c"\n'
        'int main(void) { return 0; }\n'
        '# 1 "/work/sample/src/core/engine.c"\n'
        'int core_engine(void) { return 100; }\n'
        '# 1 "/work/sample/src/plugins/sub/plugin.c"\n'
        'int sub_plugin(void) { return 200; }\n'
    )
    (out_dir / "preprocessed.c").write_text(prep_code)
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"main", "core_engine", "sub_plugin", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    res = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res["status"] == "ok"
    unexpected = [e["data"]["function"] for f in res["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "UNEXPECTED_FUNCTION"]
    missing = [e["data"]["function"] for f in res["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "MISSING_SOURCE_FUNCTION"]
    assert unexpected == []
    assert missing == []


def test_phase1_nested_source_filenames_containing_spaces(tmp_path, monkeypatch):
    """Task 4.8: Nested source filenames with spaces are preserved safely in Python and shell."""
    src = tmp_path / "src"
    (src / "deep folder").mkdir(parents=True)
    (src / "deep folder" / "spaced helper.c").write_text("int spaced_helper(void) { return 1; }\n")
    (src / "top spaced.c").write_text("int top_spaced(void) { return 2; }\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    prep_code = (
        '# 1 "/work/sample/src/deep folder/spaced helper.c"\n'
        'int spaced_helper(void) { return 1; }\n'
        '# 1 "/work/sample/src/top spaced.c"\n'
        'int top_spaced(void) { return 2; }\n'
    )
    (out_dir / "preprocessed.c").write_text(prep_code)
    (out_dir / "preprocessed.err").write_text("")
    (out_dir / "preprocessed.status").write_text("0\n")
    (out_dir / "prep_compiler.txt").write_text("compiler_id=clang\ncompiler_path=/usr/bin/clang\n")
    (out_dir / "versions.txt").write_text("clang 17\ngcc 13\n")

    monkeypatch.setattr(lab_adapter, "check", lambda: None)
    monkeypatch.setattr(lab_adapter, "run_lab", lambda *a, **kw: None)
    dummy_elf = ElfInfo(path="x", defined_funcs={"spaced_helper", "top_spaced", "_start"}, imports=set(), rodata_strings=set(), has_symtab=True)
    monkeypatch.setattr("modules.compiler_analysis.load_elf", lambda p: dummy_elf)

    res = run(str(tmp_path), options={"out_dir": str(out_dir)})
    assert res["status"] == "ok"
    unexpected = [e["data"]["function"] for f in res["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "UNEXPECTED_FUNCTION"]
    missing = [e["data"]["function"] for f in res["findings"] for e in f.get("evidence", []) if e.get("rule_id") == "MISSING_SOURCE_FUNCTION"]
    assert unexpected == []
    assert missing == []

    # Also test shell mapfile null-delimited handling directly
    import subprocess
    cmd = (
        'SRC="' + str(src) + '"\n'
        'mapfile -d "" -t FILES < <(find "$SRC" -type f -name "*.c" -print0 | sort -z)\n'
        'echo "COUNT=${#FILES[@]}"\n'
        'for f in "${FILES[@]}"; do echo "FILE=$f"; done\n'
    )
    proc = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, check=True)
    assert "COUNT=2" in proc.stdout
    assert "spaced helper.c" in proc.stdout
    assert "top spaced.c" in proc.stdout


def test_phase1_no_source_files_error_handling(tmp_path, monkeypatch):
    """Task 4.9: Fail clearly when no C source files are found in src."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "readme.txt").write_text("No C files here")

    res = run(str(tmp_path))
    assert res["status"] == "error"
    assert res["errors"][0]["code"] == "INVALID_INPUT"
    assert f"No .c files found in {src}" in res["errors"][0]["message"]

    # Also test shell script failure when no .c files exist
    import subprocess
    cmd = (
        'SRC="' + str(src) + '"\n'
        'mapfile -d "" -t FILES < <(find "$SRC" -type f -name "*.c" -print0 | sort -z)\n'
        'if [ "${#FILES[@]}" -eq 0 ]; then echo "No .c files found in $SRC" >&2; exit 1; fi\n'
    )
    proc = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
    assert proc.returncode == 1
    assert "No .c files found in" in proc.stderr
