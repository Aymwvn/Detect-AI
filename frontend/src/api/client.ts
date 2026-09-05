// API client for the DetectAI backend. Base URL is configurable via
// VITE_API_BASE_URL (.env) so the dashboard can point at any deployment
// without a rebuild-per-environment.

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

export interface Alert {
  alert_id: string;
  external_alert_id: string | null;
  timestamp: string;
  ingested_at: string;
  source: string;
  source_product: string;
  severity: string;
  rule_name: string | null;
  rule_id: string | null;
  description: string | null;
  hostname: string | null;
  username: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  process_name: string | null;
  parent_process: string | null;
  command_line: string | null;
  file_hash: string | null;
  file_name: string | null;
  domain: string | null;
  url: string | null;
  cloud_account: string | null;
  raw_event: Record<string, unknown>;
  tags: string[];
  existing_mitre_attack_mapping: { technique_id: string; technique_name: string | null; tactic: string | null }[];
  status: string;
  dedup_group_id: string | null;
  incident_id: string | null;
  risk_score: number | null;
  risk_score_breakdown: Record<string, number> | null;
  investigation_priority: string | null;
}

export interface AnalyzeResponse {
  alert_id: string;
  ai_analysis: null;
  ai_analysis_id?: string;
  message?: string;
  classification?: string;
  risk_score: number | null;
  risk_score_breakdown?: Record<string, number> | null;
  confidence?: number;
  investigation_priority: string | null;
  validation_status?: string;
  rule_based_risk_score?: number;
}

export interface FeedbackEntry {
  feedback_id: string;
  analyst_id: string;
  label: string;
  comment: string | null;
  created_at: string;
}

export interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string | null;
  url?: string | null;
}

export interface MitreMapping {
  techniques: MitreTechnique[];
  invalid_technique_ids: string[];
}

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch {
      // response wasn't JSON; fall back to statusText
    }
    throw new ApiError(response.status, detail);
  }
  if (response.status === 204) return undefined as T;
  return response.json();
}

export const api = {
  listAlerts: (limit = 50, offset = 0) =>
    request<Alert[]>(`/alerts?limit=${limit}&offset=${offset}`),

  getAlert: (alertId: string) => request<Alert>(`/alerts/${alertId}`),

  analyzeAlert: (alertId: string) =>
    request<AnalyzeResponse>(`/alerts/${alertId}/analyze`, { method: "POST" }),

  submitFeedback: (alertId: string, analystId: string, label: string, comment?: string) =>
    request<FeedbackEntry>(`/alerts/${alertId}/feedback`, {
      method: "POST",
      body: JSON.stringify({ analyst_id: analystId, label, comment }),
    }),

  listFeedback: (alertId: string) => request<FeedbackEntry[]>(`/alerts/${alertId}/feedback`),

  getAlertMitreMapping: (alertId: string) =>
    request<MitreMapping>(`/mitre/alerts/${alertId}/mapping`),
};

export { ApiError };
