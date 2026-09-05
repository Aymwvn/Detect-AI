import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type Alert, type AnalyzeResponse, type FeedbackEntry, type MitreMapping, ApiError } from "../api/client";
import { PriorityBadge, SeverityBadge } from "../components/Badge";
import "./AlertDetailPage.css";

const FIELD_LABELS: [keyof Alert, string][] = [
  ["hostname", "Hostname"],
  ["username", "Username"],
  ["source_ip", "Source IP"],
  ["destination_ip", "Destination IP"],
  ["source_port", "Source Port"],
  ["destination_port", "Destination Port"],
  ["protocol", "Protocol"],
  ["process_name", "Process"],
  ["parent_process", "Parent Process"],
  ["command_line", "Command Line"],
  ["file_hash", "File Hash"],
  ["file_name", "File Name"],
  ["domain", "Domain"],
  ["url", "URL"],
  ["cloud_account", "Cloud Account"],
];

const FEEDBACK_LABELS = [
  "true_positive",
  "false_positive",
  "benign",
  "needs_investigation",
  "confirmed_incident",
];

export function AlertDetailPage() {
  const { alertId } = useParams<{ alertId: string }>();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [mitreMapping, setMitreMapping] = useState<MitreMapping | null>(null);
  const [feedback, setFeedback] = useState<FeedbackEntry[]>([]);
  const [analysis, setAnalysis] = useState<AnalyzeResponse | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [showRawEvent, setShowRawEvent] = useState(false);
  const [analystId, setAnalystId] = useState("analyst-1");
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);

  const loadAlert = () => {
    if (!alertId) return;
    api.getAlert(alertId).then(setAlert).catch((err) => setError(errMessage(err)));
    api.getAlertMitreMapping(alertId).then(setMitreMapping).catch(() => setMitreMapping(null));
    api.listFeedback(alertId).then(setFeedback).catch(() => setFeedback([]));
  };

  useEffect(loadAlert, [alertId]);

  const handleAnalyze = async () => {
    if (!alertId) return;
    setAnalyzing(true);
    setError(null);
    try {
      const result = await api.analyzeAlert(alertId);
      setAnalysis(result);
    } catch (err) {
      setError(errMessage(err));
    } finally {
      setAnalyzing(false);
    }
  };

  const handleFeedback = async (label: string) => {
    if (!alertId) return;
    try {
      await api.submitFeedback(alertId, analystId, label, comment || undefined);
      setComment("");
      const updated = await api.listFeedback(alertId);
      setFeedback(updated);
    } catch (err) {
      setError(errMessage(err));
    }
  };

  if (error && !alert) return <div className="page-state page-error">Error: {error}</div>;
  if (!alert) return <div className="page-state">Loading…</div>;

  return (
    <div className="alert-detail">
      <Link to="/" className="back-link">
        ← Back to alerts
      </Link>

      <div className="detail-header">
        <div>
          <h1>{alert.rule_name || "Untitled alert"}</h1>
          <p className="detail-subtitle">
            {alert.source} · {new Date(alert.timestamp).toLocaleString()}
          </p>
        </div>
        <div className="detail-badges">
          <SeverityBadge value={alert.severity} />
          <PriorityBadge value={alert.investigation_priority} />
        </div>
      </div>

      {alert.description && <p className="detail-description">{alert.description}</p>}

      <div className="detail-grid">
        <section className="panel">
          <h2>Risk Score</h2>
          <div className="risk-score-value">{alert.risk_score ?? "—"}</div>
          {alert.risk_score_breakdown && (
            <table className="breakdown-table">
              <tbody>
                {Object.entries(alert.risk_score_breakdown).map(([key, value]) => (
                  <tr key={key}>
                    <td>{key.replace(/_/g, " ")}</td>
                    <td>{value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="panel">
          <h2>Evidence</h2>
          <table className="evidence-table">
            <tbody>
              {FIELD_LABELS.filter(([field]) => alert[field]).map(([field, label]) => (
                <tr key={field as string}>
                  <td className="evidence-label">{label}</td>
                  <td className="evidence-value">{String(alert[field])}</td>
                </tr>
              ))}
              {FIELD_LABELS.every(([field]) => !alert[field]) && (
                <tr>
                  <td colSpan={2} className="evidence-empty">
                    No populated evidence fields on this alert.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          <button className="link-button" onClick={() => setShowRawEvent(!showRawEvent)}>
            {showRawEvent ? "Hide" : "Show"} raw source event
          </button>
          {showRawEvent && <pre className="raw-event">{JSON.stringify(alert.raw_event, null, 2)}</pre>}
        </section>

        <section className="panel">
          <h2>MITRE ATT&CK</h2>
          {mitreMapping && mitreMapping.techniques.length > 0 ? (
            <ul className="mitre-list">
              {mitreMapping.techniques.map((t) => (
                <li key={t.technique_id}>
                  <span className="mitre-id">{t.technique_id}</span> {t.name}
                  {t.tactic && <span className="mitre-tactic"> · {t.tactic}</span>}
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty-note">No validated MITRE techniques for this alert yet.</p>
          )}
          {mitreMapping && mitreMapping.invalid_technique_ids.length > 0 && (
            <p className="mitre-invalid-note">
              Flagged (not in official ATT&CK reference data): {mitreMapping.invalid_technique_ids.join(", ")}
            </p>
          )}
        </section>

        <section className="panel">
          <h2>AI Analysis</h2>
          {!analysis && (
            <button className="primary-button" onClick={handleAnalyze} disabled={analyzing}>
              {analyzing ? "Analyzing…" : "Run AI Analysis"}
            </button>
          )}
          {analysis && analysis.ai_analysis === null && (
            <p className="empty-note">{analysis.message || "AI analysis not configured."}</p>
          )}
          {analysis && analysis.classification && (
            <div className="ai-result">
              <p>
                <strong>Classification:</strong> {analysis.classification}
              </p>
              <p>
                <strong>Confidence:</strong> {analysis.confidence}
              </p>
              <p>
                <strong>Validation:</strong> {analysis.validation_status}
              </p>
            </div>
          )}
        </section>

        <section className="panel panel-wide">
          <h2>Analyst Feedback</h2>
          <div className="feedback-form">
            <input
              className="text-input"
              value={analystId}
              onChange={(e) => setAnalystId(e.target.value)}
              placeholder="Analyst ID"
            />
            <input
              className="text-input"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder="Optional comment"
            />
            <div className="feedback-buttons">
              {FEEDBACK_LABELS.map((label) => (
                <button key={label} className="feedback-button" onClick={() => handleFeedback(label)}>
                  {label.replace(/_/g, " ")}
                </button>
              ))}
            </div>
          </div>

          {feedback.length > 0 && (
            <ul className="feedback-history">
              {feedback.map((f) => (
                <li key={f.feedback_id}>
                  <strong>{f.label.replace(/_/g, " ")}</strong> by {f.analyst_id}
                  {f.comment && <> — {f.comment}</>}
                  <span className="feedback-time"> ({new Date(f.created_at).toLocaleString()})</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      {error && <div className="page-error inline-error">Error: {error}</div>}
    </div>
  );
}

function errMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : String(err);
}
