"""Code-written explanations and limitations used when AI is unavailable or rejected."""

RULE_TEXT = {
    "TYPOSQUAT": "its name is very close to a popular package",
    "INSTALL_SCRIPT": "it runs an install script that can execute commands",
    "NEW_OR_THIN_PACKAGE": "it is new or has very little publishing history",
    "NONREGISTRY_SOURCE": "it is fetched from somewhere other than the normal registry",
    "MISSING_INTEGRITY": "its lockfile entry has no integrity hash",
    "OBFUSCATION": "it contains obfuscated-looking code",
    "PYPI_SETUP_EXEC": "its setup script runs commands when installed",
    "UNEXPECTED_FUNCTION": "a function exists in the binary that the source does not define",
    "MISSING_SOURCE_FUNCTION": "a function defined in the source is missing from the binary",
    "UNEXPECTED_IMPORT": "the binary uses library functions that the source does not use",
    "UNEXPECTED_STRING": "the binary contains text that is not in the source",
}

LIMITS = {
    "KNOWN_VULNERABILITY": "This reflects published advisories only. It says nothing about problems that have not been published.",
    "KNOWN_MALICIOUS_ADVISORY": "This rests on a published advisory. Check the advisory source before acting on it.",
    "SUSPICIOUS_INDICATOR": "Indicators are warning signs, not proof. BuildGuard has not confirmed that this package is malicious.",
    "UNRESOLVED": "BuildGuard could not complete this check, so it makes no statement either way.",
    "BUILD_MISMATCH": "A hash difference shows the files differ. It does not show why, and it is not proof of tampering.",
    "COMPILER_ANOMALY": (
        "This is a potential anomaly. The binary is compared with a list of functions derived from the source. "
        "A second compiler is used only as context, because two compilers normally produce different code. "
        "It is not proof that a compiler is compromised, and changes inside existing code, or changes present in both builds, cannot be seen this way."
    ),
    "NO_KNOWN_ISSUES": "Only the listed checks were performed. Unknown vulnerabilities, a compromised build environment and subtle compiler changes are not covered.",
}
CAVEAT_TEXT = {
    "OPTIMISED_BUILD": "This build used optimisation above -O0. Optimisation can inline or remove functions, rename them and change library calls, so function-level results are less reliable.",
    "STRIPPED_BINARY": "The binary has no symbol table (stripped), so function-level checks were skipped. Only imported functions and strings were checked.",
}
SCOPE_LIMIT = "Compiler analysis covers C programs built into Linux ELF binaries only."
SIMULATION_NOTICE = (
    "SIMULATION: this build used a wrapper script written by the BuildGuard team to imitate a compromised compiler. "
    "The extra behaviour was added on purpose for the demonstration. It is not a real compromise."
)


def _rules(finding):
    return [rule for rule in dict.fromkeys(e.get("rule_id") for e in finding.get("evidence", [])) if rule]


def _caveats(finding):
    found = (c for e in finding.get("evidence", []) for c in e.get("data", {}).get("caveats", []))
    return [c for c in dict.fromkeys(found) if c in CAVEAT_TEXT]


def limitations(finding):
    parts = [LIMITS.get(finding["category"], "")]
    if finding.get("module") == "compiler":
        parts.append(SCOPE_LIMIT)
        parts += [CAVEAT_TEXT[c] for c in _caveats(finding)]
    return " ".join(part for part in parts if part)


def simulation_notice(finding):
    return SIMULATION_NOTICE if finding.get("simulated") else ""


def explain(finding):
    category, subject = finding["category"], finding.get("subject", {})
    why = "; ".join(RULE_TEXT.get(rule, rule) for rule in _rules(finding))
    if category in ("KNOWN_VULNERABILITY", "KNOWN_MALICIOUS_ADVISORY"):
        data = next((e.get("data", {}) for e in finding.get("evidence", []) if e.get("type") == "osv_advisory"), {})
        ids = ", ".join(x for x in [data.get("id", "")] + data.get("aliases", []) if x)
        fixed = ", ".join(data.get("fixed_in", [])) or "not listed"
        return {"plain_explanation": f"{subject.get('name')} {subject.get('version')} matches a published advisory ({ids}).",
                "why_it_matters": "A published advisory means the issue is documented and may be exploitable in code that uses the affected version.",
                "recommended_actions": [f"Move to a fixed version (listed: {fixed}) and scan again."]}
    if category == "SUSPICIOUS_INDICATOR":
        return {"plain_explanation": f"{subject.get('name')} shows warning signs: {why}.",
                "why_it_matters": "These patterns are sometimes used by harmful packages, but they also appear in legitimate ones.",
                "recommended_actions": ["Do not install it until you have reviewed it.", "Check the package source and publisher."]}
    if category == "BUILD_MISMATCH":
        return {"plain_explanation": f"The compared files for {subject.get('artifact', 'this build')} are not byte-identical.",
                "why_it_matters": "Differences can come from timestamps or embedded paths, or from changes made after the trusted build.",
                "recommended_actions": ["Compare the build inputs and toolchain versions.", "Re-run the build from a fresh checkout."]}
    if category == "COMPILER_ANOMALY":
        return {"plain_explanation": "Potential compiler anomaly in the " + str(subject.get("build", "compiled")) +
                                      " build: " + why + ". The second compiler is used only as context, because two compilers normally produce different code.",
                "why_it_matters": "Behaviour that the source does not explain can come from the toolchain, so it needs a human review.",
                "recommended_actions": ["Inspect the flagged item in the disassembly.", "Rebuild with a different, trusted toolchain and compare."]}
    if category == "UNRESOLVED":
        return {"plain_explanation": f"This check could not be completed: {finding.get('title', '')}.",
                "why_it_matters": "An incomplete check gives no information about the item.",
                "recommended_actions": ["Fix the cause (for example network access or missing version information) and scan again."]}
    return {"plain_explanation": "No known issues were detected by the checks that were performed.",
            "why_it_matters": "This is not a guarantee; see the limitations.",
            "recommended_actions": ["Keep dependencies and toolchains updated and scan again after changes."]}


def overall_summary(doc):
    counts = {}
    for finding in doc["findings"]:
        if finding["category"] not in ("NO_KNOWN_ISSUES", "UNRESOLVED"):
            label = finding["category"].replace("_", " ").lower()
            counts[label] = counts.get(label, 0) + 1
    parts = []
    if counts:
        parts.append("Items for review: " + ", ".join(f"{count} {label}" for label, count in counts.items()) + ".")
    else:
        parts.append("No known issues were detected by the checks that were performed.")
    bad = [module for module, value in doc["module_status"].items() if value["status"] in ("error", "partial")]
    if bad:
        parts.append("These modules did not fully complete: " + ", ".join(bad) + ". Their results are incomplete.")
    if doc.get("simulation_present"):
        parts.append("Some compiler findings come from a simulated compromised compiler that the BuildGuard team created for demonstration.")
    return " ".join(parts)


GLOBAL_LIMITATIONS = [
    "OSV lists known issues. No match does not mean a package is free of problems.",
    "Matching hashes show two files are identical. They do not show that the source, dependencies or compiler are trustworthy.",
    "Comparing two compilers gives context only. Two compilers legitimately produce different code, so a difference is not proof of anything malicious, and agreement does not show that either compiler is trustworthy.",
    "Compiler analysis covers C programs compiled to Linux ELF binaries. Stripped or optimised binaries are analysed with reduced reliability.",
    "Findings come from deterministic checks. Explanations may be written by a language model from those findings and are validated against them.",
]
