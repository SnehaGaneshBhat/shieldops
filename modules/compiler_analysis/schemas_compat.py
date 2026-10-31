"""Use the P2 schemas when available, with a compatible local fallback."""

try:
    from backend.schemas import Evidence, Finding, ModuleResult  # type: ignore # noqa: F401
except Exception:
    from typing import Literal, Optional
    from pydantic import BaseModel, Field

    class Evidence(BaseModel):
        type: str
        rule_id: Optional[str] = None
        data: dict = Field(default_factory=dict)
        untrusted_text: list[str] = Field(default_factory=list)

    class Finding(BaseModel):
        id: str
        module: Literal["dependency", "build", "compiler", "sandbox"]
        category: Literal["KNOWN_VULNERABILITY", "KNOWN_MALICIOUS_ADVISORY", "SUSPICIOUS_INDICATOR",
                          "UNRESOLVED", "BUILD_MISMATCH", "COMPILER_ANOMALY", "NO_KNOWN_ISSUES"]
        severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
        confidence: Literal["CONFIRMED", "HIGH", "MEDIUM", "LOW"]
        subject: dict = Field(default_factory=dict)
        title: str
        evidence: list[Evidence] = Field(default_factory=list)
        file_hint: Optional[str] = None
        line_hint: Optional[int] = None

    class ModuleResult(BaseModel):
        module: str
        status: Literal["ok", "partial", "error", "skipped"]
        findings: list[Finding] = Field(default_factory=list)
        errors: list[dict] = Field(default_factory=list)
        tool_versions: dict = Field(default_factory=dict)
        duration_ms: int = 0
        checks_performed: list[str] = Field(default_factory=list)
