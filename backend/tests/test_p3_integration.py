from backend import orchestrator
from backend.schemas import Evidence, Finding, ModuleResult, Report


def test_p2_results_flow_through_p3_report_contract():
    result = ModuleResult(
        module="compiler",
        status="ok",
        checks_performed=["source_function_expectation"],
        findings=[Finding(
            id="C-001", module="compiler", category="COMPILER_ANOMALY",
            severity="MEDIUM", confidence="MEDIUM",
            subject={"build": "project", "simulated": True},
            title="[SIMULATED COMPILER COMPROMISE] unexpected function",
            evidence=[Evidence(type="rule_hit", rule_id="UNEXPECTED_FUNCTION",
                               data={"simulated_compromise": True, "caveats": []})],
        )],
    )
    results = {"compiler": result}

    findings_doc = orchestrator._correlate(results, scan_id="scan-integration")
    report = orchestrator._build_report("scan-integration", findings_doc, results, use_llm=False)
    Report.model_validate(report)

    item = report["items"][0]
    assert report["simulation_present"] is True
    assert item["simulated"] is True
    assert item["simulation_notice"].startswith("SIMULATION:")
    assert "Linux ELF" in item["limitations"]
    assert item["explanation_source"] == "template"


def test_integrated_report_html_shows_simulation_notice():
    html = orchestrator._render_html({
        "scan_id": "s1", "overall_summary": "Some simulated findings.",
        "simulation_present": True, "module_status": {}, "limitations": [],
        "items": [{"severity": "MEDIUM", "category": "COMPILER_ANOMALY", "title": "Example",
                   "plain_explanation": "Potential anomaly.", "simulation_notice": "SIMULATION: team test.",
                   "limitations": "Linux ELF only."}],
    })
    assert "this report contains findings from a compiler wrapper" in html
    assert "SIMULATION: team test." in html
    assert "Linux ELF only." in html
