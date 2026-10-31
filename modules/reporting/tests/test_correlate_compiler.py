from modules.reporting.correlate import correlate
from modules.reporting.templates import limitations, simulation_notice


def module_result(findings, status="ok"):
    return {"module": "compiler", "status": status, "findings": findings, "errors": [],
            "checks_performed": ["x"], "tool_versions": {}}


def anomaly(rule, caveats=(), sim=False):
    return {"id": "C-001", "module": "compiler", "category": "COMPILER_ANOMALY", "severity": "MEDIUM",
            "confidence": "MEDIUM", "subject": {"build": "project", "rule": rule}, "title": "x",
            "evidence": [{"type": "rule_hit", "rule_id": rule,
                          "data": {"caveats": list(caveats), "simulated_compromise": sim}, "untrusted_text": []}]}


def test_simulation_flag_and_notice_are_set_by_code():
    doc = correlate([module_result([anomaly("UNEXPECTED_FUNCTION", sim=True)])])
    assert doc["simulation_present"] is True
    assert doc["findings"][0]["simulated"] is True
    assert "SIMULATION" in simulation_notice(doc["findings"][0])


def test_caveat_lowers_confidence():
    plain = correlate([module_result([anomaly("UNEXPECTED_FUNCTION")])])["findings"][0]
    caveat = correlate([module_result([anomaly("UNEXPECTED_FUNCTION", caveats=["STRIPPED_BINARY"])])])["findings"][0]
    assert plain["confidence"] == "MEDIUM" and caveat["confidence"] == "LOW"


def test_optimised_missing_function_stays_low():
    finding = correlate([module_result([anomaly("MISSING_SOURCE_FUNCTION", caveats=["OPTIMISED_BUILD"])])])["findings"][0]
    assert finding["severity"] == "LOW"


def test_partial_clean_result_becomes_unresolved():
    clean = {"id": "C-001", "module": "compiler", "category": "NO_KNOWN_ISSUES", "severity": "INFO",
             "confidence": "LOW", "subject": {}, "title": "x", "evidence": []}
    finding = correlate([module_result([clean], status="partial")])["findings"][0]
    assert finding["category"] == "UNRESOLVED" and finding["severity"] == "INFO"


def test_limitations_state_scope_and_caveat():
    finding = correlate([module_result([anomaly("UNEXPECTED_FUNCTION", caveats=["STRIPPED_BINARY"])])])["findings"][0]
    text = limitations(finding)
    assert "Linux ELF" in text and "stripped" in text
