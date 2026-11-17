from modules.compiler_analysis.elf_utils import ElfInfo
from modules.compiler_analysis.rules import evaluate, source_functions_from_text

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


def test_gnu_attributes_with_nested_parentheses():
    code = """
    int __attribute__((aligned(sizeof(void *)), noinline)) compute(void) {
        return 0;
    }
    """
    funcs = source_functions_from_text(code)
    assert funcs == {"compute"}
    assert "__attribute__" not in funcs


def test_gnu_attributes_in_various_positions():
    code = """
    __attribute__((noinline)) int compute_prefix(void) { return 1; }
    int __attribute__((visibility("default"))) compute_mid(void) { return 2; }
    void panic_suffix(const char *msg) __attribute__((noreturn)) { exit(1); }
    __attribute__((noinline)) __attribute__((cold)) int multi_attr(void) { return 3; }
    """
    funcs = source_functions_from_text(code)
    assert funcs == {"compute_prefix", "compute_mid", "panic_suffix", "multi_attr"}
    assert "__attribute__" not in funcs


def test_multiline_function_signatures():
    code = """
    int
    compute_newline(void) {
        return 0;
    }

    static inline int
    compute_allman(
        int a,
        int b
    )
    {
        return a + b;
    }

        int
        indented_func(void) {
            return 42;
        }

    int /* return status */
    comment_between(void) {
        return 0;
    }
    """
    funcs = source_functions_from_text(code)
    assert funcs == {"compute_newline", "compute_allman", "indented_func", "comment_between"}


def test_comments_and_strings_do_not_produce_false_matches():
    code = """
    // int fake_line_comment(void) { return 0; }
    /*
    int fake_block_comment(void) {
        return 0;
    }
    */
    const char *payload = "int fake_in_string(void) { return 0; }";
    const char *braces = "}} {{{{";
    char c = '}';
    int real_func(void) {
        // if (x) { fake_nested(); }
        return 1;
    }
    """
    funcs = source_functions_from_text(code)
    assert funcs == {"real_func"}


def test_prototypes_and_function_pointers_do_not_match():
    code = """
    int proto_single(int a, int b);
    void __attribute__((noreturn)) proto_attr(void);
    int proto_multiline(
        int a,
        int b
    );
    int (*fp_var)(int, int);
    int (*fp_init)(int) = NULL;
    typedef int (*math_op)(int, int);
    typedef struct { int a; } S;

    int real_worker(void (*callback)(int, void *), int flags) {
        return 0;
    }
    """
    funcs = source_functions_from_text(code)
    assert funcs == {"real_worker"}


def test_control_flow_and_struct_enums_do_not_match():
    code = """
    struct Point {
        int x;
        int y;
        int (*draw)(int);
    };
    enum Status {
        OK = 0,
        ERR = 1
    };
    union Data {
        int i;
        float f;
    };
    #define MACRO_FUNC(x) int fake_macro(void) { return 0; }

    int process(int x) {
        if (x > 0) {
            while (x--) {
                for (int i = 0; i < 10; i++) {
                    switch (i) {
                        case 1: break;
                        default: return 0;
                    }
                }
            }
        }
        return x;
    }
    """
    funcs = source_functions_from_text(code)
    assert funcs == {"process"}


def test_specialized_c_function_definitions():
    code = """
    #ifdef __cplusplus
    extern "C" {
    #endif

    int (parenthesized_name)(void) {
        return 1;
    }

    int (*returns_function_pointer(int mode))(void) {
        return 0;
    }

    struct Result make_result(int val) {
        struct Result r = {val};
        return r;
    }

    #ifdef __cplusplus
    }
    #endif
    """
    funcs = source_functions_from_text(code)
    assert funcs == {"parenthesized_name", "returns_function_pointer", "make_result"}


def test_simulated_compiler_wrapper_inject_syntax():
    code = """
    __attribute__((constructor))
    void __bg_hidden_telemetry(void) {
        exit(1);
    }
    """
    funcs = source_functions_from_text(code)
    assert funcs == {"__bg_hidden_telemetry"}
    assert "__attribute__" not in funcs


def test_preprocessor_if_zero_behavior():
    code = """
    #if 0
    int disabled_func(void) {
        return 0;
    }
    #endif

    int active_func(void) {
        return 1;
    }
    """
    funcs = source_functions_from_text(code)
    # The parser strips directive lines (#if 0, #endif) as preprocessor directives,
    # leaving definition tokens intact; disabled_func is thus extracted.
    assert funcs == {"disabled_func", "active_func"}
