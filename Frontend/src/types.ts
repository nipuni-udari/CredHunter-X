export interface RiskScore {
  score: number;
  risk_level: string;
  recommended_action: string;
}

export interface Finding {
  finding_id: string;
  secret_type: string;
  file_path: string;
  line_number: number | null;
  redacted_secret: string | null;
  risk_level: string;
  action: string;
  decision_reason?: string;
  suppressed?: boolean;
  risk_score?: RiskScore;
  feedback?: { label: string; user?: string; reason?: string } | null;
}

export interface ProjectFindings {
  project_id: string;
  finding_count: number;
  findings: Finding[];
}

export interface FeedbackSummary {
  project_id: string;
  finding_count: number;
  suppressed_count: number;
  true_positive_count: number;
  false_positive_count: number;
  unreviewed_count: number;
}

export interface ScanDecision {
  action: string;
  exit_code: number;
  finding_count: number;
  blocking_count: number;
  manual_review_count: number;
  warning_count: number;
  ignored_count: number;
}

export interface Scan {
  scan_id: string;
  project_id: string;
  repository_name?: string;
  decision: ScanDecision;
  findings: Finding[];
}
