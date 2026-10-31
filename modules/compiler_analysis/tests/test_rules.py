from modules.compiler_analysis.elf_utils import ElfInfo
from modules.compiler_analysis.rules import evaluate

SRC = r'''int add(int a, int b) { return a + b; }
int main(void) { printf("hi\n"); return add(1, 2); }
'''
FUNCS = {"add", "main"}
RT = {"_start", "_init", "_fini"}


def info(funcs, imports=("printf",), strings=("hi",)):
    return ElfInfo(path="x", defined_funcs=set(funcs), imports=set(imports),
                   rodata_strings=set(strings), has_symtab=True)


def rules(hits):
    return {(hit["rule_id"], hit["build"]) for hit in hits}


def test_clean_has_no_hits():
    a, b = info(FUNCS | RT), info(FUNCS | RT)
    assert evaluate(a, b, FUNCS, SRC) == []


def test_injected_function_detected_in_project_only():
    a, b = info(FUNCS | RT | {"__bg_hidden_telemetry"}), info(FUNCS | RT)
    assert ("UNEXPECTED_FUNCTION", "project") in rules(evaluate(a, b, FUNCS, SRC))
    assert ("UNEXPECTED_FUNCTION", "reference") not in rules(evaluate(a, b, FUNCS, SRC))


def test_missing_source_function_detected():
    a, b = info({"main"} | RT), info(FUNCS | RT)
    assert ("MISSING_SOURCE_FUNCTION", "project") in rules(evaluate(a, b, FUNCS, SRC))


def test_puts_is_explained_by_printf():
    a, b = info(FUNCS | RT, imports=("puts",)), info(FUNCS | RT)
    assert not any(hit["rule_id"] == "UNEXPECTED_IMPORT" for hit in evaluate(a, b, FUNCS, SRC))


def test_risky_import_is_flagged_high():
    a, b = info(FUNCS | RT, imports=("printf", "system")), info(FUNCS | RT)
    hit = [item for item in evaluate(a, b, FUNCS, SRC) if item["rule_id"] == "UNEXPECTED_IMPORT"][0]
    assert hit["severity_hint"] == "HIGH" and "system" in hit["data"]["risky_imports"]


def test_unknown_string_flagged():
    a, b = info(FUNCS | RT, strings=("hi", "BEACON")), info(FUNCS | RT)
    assert ("UNEXPECTED_STRING", "project") in rules(evaluate(a, b, FUNCS, SRC))
