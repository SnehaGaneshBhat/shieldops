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
