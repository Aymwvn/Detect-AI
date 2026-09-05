import "./Badge.css";

const SEVERITY_CLASS: Record<string, string> = {
  critical: "badge-critical",
  high: "badge-high",
  medium: "badge-medium",
  low: "badge-low",
  informational: "badge-info",
  unknown: "badge-unknown",
};

export function SeverityBadge({ value }: { value: string }) {
  const cls = SEVERITY_CLASS[value] || SEVERITY_CLASS.unknown;
  return <span className={`badge ${cls}`}>{value}</span>;
}

export function PriorityBadge({ value }: { value: string | null }) {
  if (!value) return <span className="badge badge-unknown">—</span>;
  const cls = SEVERITY_CLASS[value] || SEVERITY_CLASS.unknown;
  return <span className={`badge ${cls}`}>{value}</span>;
}

export function StatusBadge({ value }: { value: string }) {
  return <span className="badge badge-status">{value.replace(/_/g, " ")}</span>;
}
