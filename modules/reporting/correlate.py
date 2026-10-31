"""Deterministic correlation, severity assignment, and stable report IDs."""

import json
from datetime import datetime, timezone

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "INFO": 5}


def _rules(finding):
    return {e.get("rule_id") for e in finding.get("evidence", []) if e.get("rule_id")}


def _cap_untrusted(finding):
    for evidence in finding.get("evidence", []):
        cleaned = ["".join(ch for ch in text if ch.isprintable())[:300]
                   for text in evidence.get("untrusted_text", []) if isinstance(text, str)]
        evidence["untrusted_text"] = cleaned[:10]


def _final(finding, siblings):
    category, rules = finding["category"], _rules(finding)
    if category == "KNOWN_VULNERABILITY":
        finding["confidence"] = "CONFIRMED"
        if finding.get("severity") not in SEV_ORDER:
            finding["severity"] = "UNKNOWN"
    elif category == "KNOWN_MALICIOUS_ADVISORY":
        finding["severity"], finding["confidence"] = "CRITICAL", "CONFIRMED"
    elif category == "SUSPICIOUS_INDICATOR":
        n = len(rules)
        if n >= 3:
            finding["severity"], finding["confidence"] = "HIGH", "HIGH"
        elif n == 2:
            finding["severity"], finding["confidence"] = "HIGH", "MEDIUM"
        else:
            finding["severity"] = "MEDIUM" if "INSTALL_SCRIPT" in rules else "LOW"
            finding["confidence"] = "LOW"
    elif category == "BUILD_MISMATCH":
        subtype = finding.get("subject", {}).get("subtype") or next(
            (e.get("data", {}).get("subtype") for e in finding.get("evidence", [])
             if e.get("data", {}).get("subtype")), None)
        benign = any(e.get("data", {}).get("benign_hint") for e in finding.get("evidence", []))
        if subtype == "POST_BUILD_DIFF":
            finding["severity"], finding["confidence"] = "HIGH", "HIGH"
        elif benign:
            finding["severity"], finding["confidence"] = "MEDIUM", "LOW"
        else:
            finding["severity"], finding["confidence"] = "HIGH", "MEDIUM"
    elif category == "COMPILER_ANOMALY":
        caveats = {c for e in finding.get("evidence", []) for c in e.get("data", {}).get("caveats", [])}
        finding["confidence"] = "LOW" if caveats else "MEDIUM"
        build = finding.get("subject", {}).get("build")
        corroborated = any(s is not finding and s.get("category") == "COMPILER_ANOMALY"
                           and s.get("subject", {}).get("build") == build for s in siblings)
        if "OPTIMISED_BUILD" in caveats and rules == {"MISSING_SOURCE_FUNCTION"}:
            finding["severity"] = "LOW"
        elif rules & {"UNEXPECTED_FUNCTION", "MISSING_SOURCE_FUNCTION"}:
            finding["severity"] = "HIGH" if corroborated and not caveats else "MEDIUM"
        elif finding.get("severity") not in SEV_ORDER:
            finding["severity"] = "LOW"
    else:
        finding["severity"], finding["confidence"] = "INFO", "LOW"


def _allowed_ids(findings):
    ids = {finding["id"] for finding in findings}
    for finding in findings:
        for evidence in finding.get("evidence", []):
            data = evidence.get("data", {})
            if isinstance(data.get("id"), str):
                ids.add(data["id"])
            ids.update(alias for alias in data.get("aliases", []) if isinstance(alias, str))
    return sorted(ids)


def _correlations(findings):
    group = lambda cats: [f["id"] for f in findings if f["category"] in cats]
    suspicious = group(("SUSPICIOUS_INDICATOR", "KNOWN_MALICIOUS_ADVISORY"))
    mismatches = group(("BUILD_MISMATCH",))
    anomalies = group(("COMPILER_ANOMALY",))
    note = "Signals from different modules coincide. This raises the priority for human review; it does not establish a cause."
    output = []
    for left, right in ((suspicious, mismatches), (anomalies, mismatches), (suspicious, anomalies)):
        if left and right:
            output.append({"id": f"X-{len(output) + 1:03d}", "finding_ids": left + right, "note": note})
    return output


def correlate(results, scan_id=None):
    findings, module_status, versions = [], {}, {}
    for result in results:
        module_status[result["module"]] = {"status": result["status"], "errors": result.get("errors", []),
                                           "checks_performed": result.get("checks_performed", [])}
        versions[result["module"]] = result.get("tool_versions", {})
        for original in result.get("findings", []):
            finding = json.loads(json.dumps(original))
            finding["source_id"] = finding["id"]
            if result["status"] == "partial" and finding["category"] == "NO_KNOWN_ISSUES":
                finding["category"], finding["title"] = "UNRESOLVED", "Checks incomplete for module " + result["module"]
            _cap_untrusted(finding)
            findings.append(finding)
    for finding in findings:
        _final(finding, findings)
        finding["simulated"] = any(e.get("data", {}).get("simulated_compromise")
                                   for e in finding.get("evidence", []))
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["module"], f["source_id"]))
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"F-{index:03d}"
    return {
        "scan_id": scan_id or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_versions": versions, "module_status": module_status, "findings": findings,
        "correlations": _correlations(findings), "allowed_ids": _allowed_ids(findings),
        "simulation_present": any(f["simulated"] for f in findings),
    }
