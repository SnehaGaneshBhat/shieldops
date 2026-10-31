"""Validate model output before it can enter a BuildGuard report."""

import re

ID_RE = re.compile(r"\b(?:F-\d{3}|CVE-\d{4}-\d+|GHSA-[A-Za-z0-9-]+|MAL-\d+)\b", re.I)
FORBIDDEN_GENERAL = ("safe", "clean", "secure", "verified", "trustworthy")


class InvalidExplanation(ValueError):
    pass


def _text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise InvalidExplanation(f"{field} must be a non-empty string")
    return value.strip()


def validate_response(payload, findings_doc):
    """Return a normalised model response or reject the entire response."""
    if not isinstance(payload, dict):
        raise InvalidExplanation("response must be a JSON object")
    if set(payload) != {"overall_summary", "explanations"}:
        raise InvalidExplanation("response has an unexpected JSON shape")
    summary = _text(payload["overall_summary"], "overall_summary")
    if not 2 <= len(re.findall(r"[.!?](?:\s|$)", summary)) <= 4:
        raise InvalidExplanation("overall_summary must contain 2 to 4 sentences")
    if not isinstance(payload["explanations"], list):
        raise InvalidExplanation("explanations must be a list")
    expected = [finding["id"] for finding in findings_doc.get("findings", [])]
    if len(payload["explanations"]) != len(expected):
        raise InvalidExplanation("one explanation is required for every finding")
    allowed = set(findings_doc.get("allowed_ids", []))
    allowed.update(expected)
    clean = []
    for expected_id, item in zip(expected, payload["explanations"]):
        if not isinstance(item, dict) or set(item) != {"finding_id", "plain_explanation", "why_it_matters", "recommended_actions"}:
            raise InvalidExplanation("explanation has an unexpected JSON shape")
        if item["finding_id"] != expected_id:
            raise InvalidExplanation("finding explanations are missing, reordered, or duplicated")
        explanation = {
            "finding_id": expected_id,
            "plain_explanation": _text(item["plain_explanation"], "plain_explanation"),
            "why_it_matters": _text(item["why_it_matters"], "why_it_matters"),
            "recommended_actions": item["recommended_actions"],
        }
        actions = explanation["recommended_actions"]
        if not isinstance(actions, list) or not actions or any(not isinstance(a, str) or not a.strip() for a in actions):
            raise InvalidExplanation("recommended_actions must be a non-empty list of strings")
        clean.append(explanation)
    all_text = summary + " " + " ".join(
        item["plain_explanation"] + " " + item["why_it_matters"] + " " + " ".join(item["recommended_actions"])
        for item in clean)
    for mention in ID_RE.findall(all_text):
        if mention not in allowed:
            raise InvalidExplanation(f"unsupported identifier: {mention}")
    lowered = all_text.lower()
    if any(re.search(r"\b" + re.escape(word) + r"\b", lowered) for word in FORBIDDEN_GENERAL):
        raise InvalidExplanation("response contains prohibited certainty or reassurance language")
    categories = {finding["category"] for finding in findings_doc.get("findings", [])}
    if "KNOWN_MALICIOUS_ADVISORY" not in categories and re.search(r"\b(malicious|malware|backdoor)\b", lowered):
        raise InvalidExplanation("response makes an unsupported maliciousness claim")
    if findings_doc.get("simulation_present") and re.search(r"\bcompromised\b", lowered):
        raise InvalidExplanation("model text must not describe simulated findings as compromised")
    return {"overall_summary": summary, "explanations": clean}
