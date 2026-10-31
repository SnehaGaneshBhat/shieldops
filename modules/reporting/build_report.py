"""Combine correlated findings with validated explanations and code-written notices."""

import json

from . import llm_client
from .templates import GLOBAL_LIMITATIONS, explain, limitations, overall_summary, simulation_notice
from .validate import InvalidExplanation, validate_response


def _template_response(findings_doc):
    return {"overall_summary": overall_summary(findings_doc),
            "explanations": [{"finding_id": finding["id"], **explain(finding)}
                             for finding in findings_doc.get("findings", [])]}


def build_report(findings_doc, use_llm=True):
    """Return a report dictionary. Deterministic templates are the default fallback."""
    response = _template_response(findings_doc)
    explanation_source = "template"
    if use_llm and llm_client.llm_configured():
        try:
            raw = llm_client.cached_or_call(llm_client.build_user_message(findings_doc))
            response = validate_response(json.loads(raw), findings_doc)
            explanation_source = "llm_validated"
        except (Exception, InvalidExplanation):
            # A malformed, unsupported, or unavailable model response never blocks the report.
            response = _template_response(findings_doc)
            explanation_source = "template_fallback"
    explanation_by_id = {item["finding_id"]: item for item in response["explanations"]}
    items = []
    for finding in findings_doc.get("findings", []):
        item = dict(finding)
        explanation = dict(explanation_by_id.get(finding["id"], explain(finding)))
        explanation.pop("finding_id", None)
        item.update(explanation)
        item["limitations"] = limitations(finding)
        item["simulation_notice"] = simulation_notice(finding)
        items.append(item)
    return {
        "scan_id": findings_doc.get("scan_id"),
        "generated_at": findings_doc.get("generated_at"),
        "overall_summary": response["overall_summary"],
        "explanation_source": explanation_source,
        "items": items,
        "correlations": findings_doc.get("correlations", []),
        "module_status": findings_doc.get("module_status", {}),
        "tool_versions": findings_doc.get("tool_versions", {}),
        "allowed_ids": findings_doc.get("allowed_ids", []),
        "simulation_present": bool(findings_doc.get("simulation_present")),
        "global_limitations": list(GLOBAL_LIMITATIONS),
    }
