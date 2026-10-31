from typing import Literal, Optional
from pydantic import BaseModel, Field


Category = Literal[
    'KNOWN_VULNERABILITY', 'KNOWN_MALICIOUS_ADVISORY',
    'SUSPICIOUS_INDICATOR',
    'UNRESOLVED', 'BUILD_MISMATCH', 'COMPILER_ANOMALY', 'NO_KNOWN_ISSUES',
]

Severity = Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']
Confidence = Literal['CONFIRMED', 'HIGH', 'MEDIUM', 'LOW']


class Evidence(BaseModel):
    type: str  # osv_advisory, rule_hit, hash_pair, symbol_diff, tool_output
    rule_id: Optional[str] = None
    data: dict = Field(default_factory=dict)  # structured facts only
    untrusted_text: list[str] = Field(default_factory=list)  # capped, sanitised


class Finding(BaseModel):
    id: str  # module gives a temporary id; correlation assigns F-001...
    module: Literal['dependency', 'build', 'compiler', 'sandbox']
    category: Category
    severity: Severity
    confidence: Confidence
    subject: dict = Field(default_factory=dict)
    title: str  # short, deterministic, template-generated
    evidence: list[Evidence] = Field(default_factory=list)
    file_hint: Optional[str] = None  # for VS Code Diagnostics
    line_hint: Optional[int] = None


class ModuleResult(BaseModel):
    module: str
    status: Literal['ok', 'partial', 'error', 'skipped']
    findings: list[Finding] = Field(default_factory=list)
    errors: list[dict] = Field(default_factory=list)  # {code, message, detail}
    tool_versions: dict = Field(default_factory=dict)
    duration_ms: int = 0
    checks_performed: list[str] = Field(default_factory=list)


class Report(BaseModel):
    scan_id: str
    generated_at: str
    overall_summary: str
    summary_counts: dict
    items: list[dict]  # finding + explanation + explanation_source (llm|template)
    module_status: dict
    limitations: list[str]


# ---- API request models ----

class ScanOptions(BaseModel):
    use_llm: bool = True
    recipe_path: str = 'buildguard.yml'
    manifest_path: Optional[str] = None
    distributed_artifact: Optional[str] = None
    compiler_sample: Optional[str] = None
    run_sandbox: bool = False
    allow_unpinned: bool = False  # dev only: build with an image tag, not a digest
    docker_timeout: int = 120


class ScanRequest(BaseModel):
    project_path: str
    modules: list[Literal['dependency', 'build', 'compiler']] = Field(
        default_factory=lambda: ['dependency', 'build', 'compiler']
    )
    options: ScanOptions = Field(default_factory=ScanOptions)


class ManifestRequest(BaseModel):
    project_path: str
    recipe_path: str = 'buildguard.yml'
    allow_unpinned: bool = False


class VerifyRequest(BaseModel):
    manifest_path: str
    distributed_artifact: str
