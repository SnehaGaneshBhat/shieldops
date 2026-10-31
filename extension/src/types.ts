export type Category =
  | 'KNOWN_VULNERABILITY'
  | 'KNOWN_MALICIOUS_ADVISORY'
  | 'SUSPICIOUS_INDICATOR'
  | 'UNRESOLVED'
  | 'BUILD_MISMATCH'
  | 'COMPILER_ANOMALY'
  | 'NO_KNOWN_ISSUES';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNKNOWN';
export type Confidence = 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Evidence {
  type: string;
  rule_id?: string | null;
  data?: Record<string, unknown>;
  untrusted_text?: string[];
}

export interface Explanation {
  plain_explanation?: string;
  why_it_matters?: string;
  recommended_actions?: string[];
  limitations?: string;
}

export interface ReportItem {
  id: string;
  module: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  subject?: Record<string, unknown>;
  title: string;
  evidence?: Evidence[];
  file_hint?: string | null;
  line_hint?: number | null;

  // Accept nested fixture reports and the flattened backend report contract.
  explanation?: Explanation;
  plain_explanation?: string;
  why_it_matters?: string;
  recommended_actions?: string[];
  limitations?: string;
  simulation_notice?: string;
  explanation_source?: string;
  simulated?: boolean;
}

export interface Report {
  scan_id: string;
  generated_at: string;
  overall_summary: string;
  summary_counts?: Record<string, unknown>;
  items: ReportItem[];
  module_status?: Record<string, unknown>;
  limitations?: string[];
  global_limitations?: string[];
  explanation_source?: string;
  simulation_present?: boolean;
}

export interface ScanRequest {
  project_path: string;
  modules: string[];
  options: {
    use_llm: boolean;
    recipe_path: string;
    manifest_path: string | null;
    distributed_artifact: string | null;
    compiler_sample: string;
    run_sandbox: boolean;
  };
}

export type ScanState = 'queued' | 'running' | 'completed' | 'completed_with_errors' | 'failed' | 'cancelled';

export interface ScanStatus {
  scan_id: string;
  state: ScanState;
  modules: Record<string, string>;
  errors: unknown[];
  started_at: string;
}
