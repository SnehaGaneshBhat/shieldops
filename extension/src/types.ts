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

  // Nested shape used by the current extension mock.
  explanation?: Explanation;

  // Flattened shape emitted by modules/reporting/build_report.py.
  plain_explanation?: string;
  why_it_matters?: string;
  recommended_actions?: string[];
  limitations?: string;

  explanation_source?: string;
}

export interface Report {
  scan_id: string;
  generated_at: string;
  overall_summary: string;
  summary_counts?: Record<string, unknown>;
  items: ReportItem[];
  module_status?: Record<string, unknown>;

  // The current mock/API shape.
  limitations?: string[];

  // The report builder’s current output shape.
  global_limitations?: string[];
  explanation_source?: string;
}
