"""
Generic webhook & generic REST connectors.

Unlike Elastic/Splunk/Wazuh, there's no fixed schema to map against here —
by definition, "generic" means the source could be anything: a custom
script, an unlisted product, an internal tool. So instead of hardcoded
field names, normalization tries a list of common aliases per CAS field
(e.g. hostname could arrive as "hostname", "host", or "host_name") and
takes the first one present.

Two connector shapes, both sharing that normalization logic:

- GenericWebhookConnector: PUSH-based. The source POSTs alerts to
  DetectAI's own ingestion endpoint; this connector has nothing to poll,
  so fetch_alerts() correctly raises NotSupportedError. Its job is
  normalize_event() plus HMAC signature verification for inbound requests
  (see verify_signature) — since a public-facing webhook endpoint is
  exactly the kind of untrusted-input surface architecture doc section 14
  warns about.
- GenericRESTConnector: PULL-based. Polls a configurable REST endpoint
  and expects a JSON array (or a dict with a configurable results key).

Severity note: numeric severity from an unknown source is inherently
ambiguous (a "7" could mean CVSS 0-10, Wazuh 0-15, or something else
entirely). `_normalize_severity` makes a best-effort proportional guess
against a configurable `severity_max` (default 10, i.e. assumes a
CVSS-like scale) — deployments with a different convention should set
`severity_max` in connector config accordingly, or better, map to a
string severity ("low"/"medium"/"high"/"critical") on the sending side
if at all possible.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from typing import Any

from app.schemas import CommonAlertSchema, Severity, SourceProduct
from connectors.base import RawAlert, SIEMConnector
from connectors.exceptions import ConnectorAuthError, ConnectorFetchError, NotSupportedError

# Field -> list of accepted incoming key names, tried in order.
DEFAULT_FIELD_ALIASES: dict[str, list[str]] = {
    "external_alert_id": ["id", "alert_id", "event_id"],
    "timestamp": ["timestamp", "time", "@timestamp", "detected_at", "created_at"],
    "severity": ["severity", "level", "priority"],
    "rule_name": ["rule_name", "rule", "title", "name", "signature"],
    "rule_id": ["rule_id", "ruleId"],
    "description": ["description", "message", "summary"],
    "hostname": ["hostname", "host", "host_name", "computer_name"],
    "username": ["username", "user", "user_name", "account"],
    "source_ip": ["source_ip", "src_ip", "srcip", "src"],
    "destination_ip": ["destination_ip", "dest_ip", "dst_ip", "dstip", "dest"],
    "source_port": ["source_port", "src_port", "srcport"],
    "destination_port": ["destination_port", "dest_port", "dst_port", "dstport"],
    "protocol": ["protocol", "transport", "proto"],
    "process_name": ["process_name", "process", "image", "process_image"],
    "parent_process": ["parent_process", "parent_process_name", "parent_image"],
    "command_line": ["command_line", "cmdline", "commandLine", "cmd"],
    "file_hash": ["file_hash", "hash", "sha256", "md5"],
    "file_name": ["file_name", "filename", "file"],
    "domain": ["domain", "dns_query", "query"],
    "url": ["url", "uri"],
    "cloud_account": ["cloud_account", "account_id", "aws_account_id"],
    "tags": ["tags", "tag", "labels"],
}

_STRING_SEVERITY_SYNONYMS = {
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
}


def _first_present(raw: dict[str, Any], aliases: list[str]) -> Any:
    """Case-insensitive lookup across a list of candidate keys, returning
    the first one actually present in the payload (even if its value is
    falsy, e.g. 0 or ""; only truly absent keys are skipped)."""
    lowered = {str(k).lower(): v for k, v in raw.items()}
    for alias in aliases:
        key = alias.lower()
        if key in lowered:
            return lowered[key]
    return None


def _normalize_severity(value: Any, severity_max: float = 10.0) -> Severity:
    if value is None:
        return Severity.UNKNOWN
    if isinstance(value, str):
        return _STRING_SEVERITY_SYNONYMS.get(value.strip().lower(), Severity.UNKNOWN)
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return Severity.UNKNOWN

    if severity_max <= 0:
        return Severity.UNKNOWN
    ratio = numeric / severity_max
    if ratio < 0.25:
        return Severity.LOW
    if ratio < 0.5:
        return Severity.MEDIUM
    if ratio < 0.75:
        return Severity.HIGH
    return Severity.CRITICAL


def _normalize_timestamp(value: Any) -> datetime:
    if value is None:
        return datetime.now().astimezone()
    if isinstance(value, (int, float)):
        # Heuristic: treat values above ~1e12 as milliseconds, not seconds.
        seconds = value / 1000 if value > 1e12 else value
        return datetime.fromtimestamp(seconds).astimezone()
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now().astimezone()
    return datetime.now().astimezone()


def _normalize_tags(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(t) for t in value]
    if isinstance(value, str):
        # Accept either a single tag or a comma-separated list.
        return [t.strip() for t in value.split(",") if t.strip()]
    return []


def _to_int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_generic_alert(
    raw: RawAlert,
    source_name: str,
    source_product: SourceProduct,
    field_aliases: dict[str, list[str]] | None = None,
    severity_max: float = 10.0,
) -> CommonAlertSchema:
    """Shared normalization logic for both generic connectors."""
    aliases = field_aliases or DEFAULT_FIELD_ALIASES
    get = lambda field: _first_present(raw, aliases.get(field, [field]))  # noqa: E731

    return CommonAlertSchema(
        external_alert_id=get("external_alert_id"),
        timestamp=_normalize_timestamp(get("timestamp")),
        source=source_name,
        source_product=source_product,
        severity=_normalize_severity(get("severity"), severity_max=severity_max),
        rule_name=get("rule_name"),
        rule_id=get("rule_id"),
        description=get("description"),
        hostname=get("hostname"),
        username=get("username"),
        source_ip=get("source_ip"),
        destination_ip=get("destination_ip"),
        source_port=_to_int_or_none(get("source_port")),
        destination_port=_to_int_or_none(get("destination_port")),
        protocol=get("protocol"),
        process_name=get("process_name"),
        parent_process=get("parent_process"),
        command_line=get("command_line"),
        file_hash=get("file_hash"),
        file_name=get("file_name"),
        domain=get("domain"),
        url=get("url"),
        cloud_account=get("cloud_account"),
        tags=_normalize_tags(get("tags")),
        raw_event=raw,
    )


class GenericWebhookConnector(SIEMConnector):
    """PUSH-based: the source calls DetectAI, not the other way around.
    fetch_alerts() is intentionally unsupported — see module docstring."""

    source_product = SourceProduct.GENERIC_WEBHOOK.value

    def __init__(self, connector_id: str, name: str, config: dict[str, Any] | None = None):
        super().__init__(connector_id, name, config)
        self.field_aliases = self.config.get("field_aliases") or DEFAULT_FIELD_ALIASES
        self.severity_max = float(self.config.get("severity_max", 10.0))
        self.shared_secret = self.config.get("shared_secret")

    def authenticate(self) -> bool:
        """For a push connector, "authenticate" means "is this connector
        configured to be able to verify inbound requests" — there's nothing
        to call outward to. A webhook with no shared_secret accepts
        unauthenticated requests, which callers should treat as a
        configuration warning, not silently allow in production."""
        if not self.shared_secret:
            raise ConnectorAuthError(
                f"GenericWebhookConnector '{self.name}': no shared_secret configured — "
                "inbound requests cannot be authenticated"
            )
        return True

    def fetch_alerts(self, since: datetime) -> list[RawAlert]:
        raise NotSupportedError("fetch_alerts", self.name)

    def verify_signature(self, payload: bytes, signature_header: str | None) -> bool:
        """Validates an inbound webhook request using HMAC-SHA256 over the
        raw request body, compared with constant-time comparison to avoid
        timing side-channels. Callers (the ingestion API endpoint) MUST call
        this before trusting any inbound payload — see architecture doc
        section 14 (all connector data is untrusted) and section 15
        (prompt injection defense starts with knowing the sender is real)."""
        if not self.shared_secret or not signature_header:
            return False
        expected = hmac.new(self.shared_secret.encode(), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature_header)

    def normalize_event(self, raw: RawAlert) -> CommonAlertSchema:
        return normalize_generic_alert(
            raw,
            source_name=self.name,
            source_product=SourceProduct.GENERIC_WEBHOOK,
            field_aliases=self.field_aliases,
            severity_max=self.severity_max,
        )


class GenericRESTConnector(SIEMConnector):
    """PULL-based: polls a configurable REST endpoint expecting a JSON
    array, or a JSON object with results under a configurable key
    (default tries "results", "alerts", "data" in that order)."""

    source_product = SourceProduct.GENERIC_REST.value

    def __init__(
        self,
        connector_id: str,
        name: str,
        config: dict[str, Any] | None = None,
        client: Any | None = None,
    ):
        super().__init__(connector_id, name, config)
        self.field_aliases = self.config.get("field_aliases") or DEFAULT_FIELD_ALIASES
        self.severity_max = float(self.config.get("severity_max", 10.0))
        self.results_key = self.config.get("results_key")  # None = auto-detect
        self._client = client

    def _build_client(self) -> Any:
        base_url = self.config.get("base_url")
        if not base_url:
            raise ConnectorAuthError(f"GenericRESTConnector '{self.name}': missing 'base_url' in config")

        try:
            import httpx
        except ImportError as exc:
            raise ConnectorFetchError(
                "The 'httpx' package is required for GenericRESTConnector. Install with: pip install httpx"
            ) from exc

        headers = {}
        api_key = self.config.get("api_key")
        if api_key:
            header_name = self.config.get("api_key_header", "Authorization")
            header_value = f"Bearer {api_key}" if header_name == "Authorization" else api_key
            headers[header_name] = header_value

        return httpx.Client(
            base_url=base_url,
            headers=headers,
            verify=self.config.get("verify_ssl", True),
            timeout=self.config.get("timeout_seconds", 30),
        )

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def authenticate(self) -> bool:
        path = self.config.get("health_path", "/")
        try:
            response = self.client.get(path)
        except Exception as exc:
            raise ConnectorAuthError(f"GenericRESTConnector '{self.name}' auth failed: {exc}") from exc
        if response.status_code == 401:
            raise ConnectorAuthError(f"GenericRESTConnector '{self.name}': invalid credentials")
        if response.status_code >= 400:
            raise ConnectorAuthError(
                f"GenericRESTConnector '{self.name}' auth failed: HTTP {response.status_code}"
            )
        return True

    def fetch_alerts(self, since: datetime) -> list[RawAlert]:
        path = self.config.get("alerts_path", "/alerts")
        params = {self.config.get("since_param", "since"): since.isoformat()}
        try:
            response = self.client.get(path, params=params)
        except Exception as exc:
            raise ConnectorFetchError(f"GenericRESTConnector '{self.name}' fetch_alerts failed: {exc}") from exc

        if response.status_code >= 400:
            raise ConnectorFetchError(
                f"GenericRESTConnector '{self.name}' fetch_alerts failed: HTTP {response.status_code}"
            )

        body = response.json()
        return self._extract_results(body)

    def _extract_results(self, body: Any) -> list[RawAlert]:
        if isinstance(body, list):
            return body
        if isinstance(body, dict):
            if self.results_key:
                return body.get(self.results_key, [])
            for key in ("results", "alerts", "data"):
                if key in body:
                    return body[key]
        raise ConnectorFetchError(
            f"GenericRESTConnector '{self.name}': could not find a results list in the response "
            f"(configure 'results_key' if the source uses a non-standard wrapper field)"
        )

    def normalize_event(self, raw: RawAlert) -> CommonAlertSchema:
        return normalize_generic_alert(
            raw,
            source_name=self.name,
            source_product=SourceProduct.GENERIC_REST,
            field_aliases=self.field_aliases,
            severity_max=self.severity_max,
        )
