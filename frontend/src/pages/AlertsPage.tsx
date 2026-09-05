import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Alert, ApiError } from "../api/client";
import { PriorityBadge, SeverityBadge } from "../components/Badge";
import "./AlertsPage.css";

export function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const data = await api.listAlerts();
        if (!cancelled) {
          setAlerts(data);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof ApiError ? err.message : "Failed to load alerts");
          setLoading(false);
        }
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) return <div className="page-state">Loading alerts…</div>;
  if (error) return <div className="page-state page-error">Error: {error}</div>;

  return (
    <div className="alerts-page">
      <h1>Alerts</h1>
      {alerts.length === 0 ? (
        <div className="page-state">No alerts yet. Ingest one via the API to see it here.</div>
      ) : (
        <table className="alerts-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Priority</th>
              <th>Rule</th>
              <th>Host</th>
              <th>Source</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.alert_id}>
                <td>
                  <SeverityBadge value={alert.severity} />
                </td>
                <td>
                  <PriorityBadge value={alert.investigation_priority} />
                </td>
                <td>
                  <Link to={`/alerts/${alert.alert_id}`}>{alert.rule_name || "(no rule name)"}</Link>
                </td>
                <td>{alert.hostname || "—"}</td>
                <td>{alert.source}</td>
                <td>{new Date(alert.timestamp).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
