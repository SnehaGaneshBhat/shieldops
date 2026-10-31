from typing import Literal, Optional
from pydantic import BaseModel


Category = Literal[
    'KNOWN_VULNERABILITY',
    'KNOWN_MALICIOUS_ADVISORY',
    'SUSPICIOUS_INDICATOR',
    'UNRESOLVED',
    'BUILD_MISMATCH',
    'COMPILER_ANOMALY',
    'NO_KNOWN_ISSUES'
]

Severity = Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']
Confidence = Literal['CONFIRMED', 'HIGH', 'MEDIUM', 'LOW']


class Evidence(BaseModel):
    type: str
    rule_id: Optional[str] = None
    data: dict
    untrusted_text: list[str] = []


class Finding(BaseModel):
    id: str
    module: Literal['dependency', 'build', 'compiler', 'sandbox']
    category: Category
    severity: Severity
    confidence: Confidence
    subject: dict
    title: str
    evidence: list[Evidence]
    file_hint: Optional[str] = None
    line_hint: Optional[int] = None


class ModuleResult(BaseModel):
    module: str
    status: Literal['ok', 'partial', 'error', 'skipped']
    findings: list[Finding] = []
    errors: list[dict] = []
    tool_versions: dict = {}
    duration_ms: int = 0
    checks_performed: list[str] = []