"""
Splunk connector.

Uses Splunk's REST API oneshot search (exec_mode=oneshot) against the
Enterprise Security "notable" index by default — this is the standard
location for correlated security alerts in a Splunk ES deployment. The
search query itself is configurable, so a deployment without ES (plain
Splunk Enterprise with custom alert-generating searches) can point this
connector at whatever index/search produces its alerts instead.

Uses httpx (already a project dependency) rather than adding `requests`,
since httpx's sync Client covers everything needed here and keeps the
dependency surface smaller.

Testing note: pass `client=<your own object>` to __init__ to inject a fake
HTTP client (see tests/test_splunk_connector.py) — no real Splunk instance
is reachable from this environment, so tests verify DetectAI's own query
construction and field-mapping logic against a fake client shaped like
httpx.Client (.get()/.post() returning objects with .status_code/.json()).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.schemas import CommonAlertSchema, Severity, SourceProduct
from connectors.base import RawAlert, SIEMConnector
from connectors.exceptions import ConnectorAuthError, ConnectorFetchError

DEFAULT_INDEX = "notable"
DEFAULT_PAGE_SIZE = 200

# Splunk ES uses "urgency" for notable events, values below. Kept as an
# explicit table (see same rationale in connectors/elastic.py) rather than
# a bare pass-through.
_URGENCY_MAP = {
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class SplunkConnector(SIEMConnector):
    source_product = SourceProduct.SPLUNK.value

    def __init__(
        self,
        connector_id: str,
        name: str,
        config: dict[str, Any] | None = None,
        client: Any | None = None,
    ):
        super().__init__(connector_id, name, config)
        self.index = self.config.get("index", DEFAULT_INDEX)
        self.page_size = int(self.config.get("page_size", DEFAULT_PAGE_SIZE))
        # Override to point at a custom alert-generating search instead of
        # the default ES notable-events index scan.
        self.search_override = self.config.get("search")
        self._client = client

    # --- client lifecycle -------------------------------------------------------

    def _build_client(self) -> Any:
        try:
            import httpx
        except ImportError as exc:
            raise ConnectorFetchError(
                "The 'httpx' package is required for SplunkConnector. Install with: pip install httpx"
            ) from exc

        base_url = self.config.get("base_url")
        if not base_url:
            raise ConnectorAuthError(f"SplunkConnector '{self.name}': missing 'base_url' in config")

        token = self.config.get("token")
        headers = {"Authorization": f"Bearer {token}"} if token else {}

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

    # --- required interface --------------------------------------------------

    def authenticate(self) -> bool:
        try:
            response = self.client.get("/services/server/info", params={"output_mode": "json"})
        except Exception as exc:
            raise ConnectorAuthError(f"SplunkConnector '{self.name}' auth failed: {exc}") from exc

        if response.status_code == 401:
            raise ConnectorAuthError(f"SplunkConnector '{self.name}': invalid or expired token")
        if response.status_code >= 400:
            raise ConnectorAuthError(
                f"SplunkConnector '{self.name}' auth failed: HTTP {response.status_code}"
            )
        return True

    def fetch_alerts(self, since: datetime) -> list[RawAlert]:
        search = self.search_override or f"search index={self.index}"
        params = {
            "search": search,
            "output_mode": "json",
            "exec_mode": "oneshot",
            "earliest_time": since.isoformat(),
            "latest_time": "now",
            "count": self.page_size,
        }
        try:
            response = self.client.post("/services/search/jobs", data=params)
        except Exception as exc:
            raise ConnectorFetchError(f"SplunkConnector '{self.name}' fetch_alerts failed: {exc}") from exc

        if response.status_code >= 400:
            raise ConnectorFetchError(
                f"SplunkConnector '{self.name}' fetch_alerts failed: HTTP {response.status_code}"
            )

        body = response.json()
        return body.get("results", [])

    def get_alert(self, alert_id: str) -> RawAlert:
        params = {
            "search": f'search index={self.index} event_id="{alert_id}"',
            "output_mode": "json",
            "exec_mode": "oneshot",
            "count": 1,
        }
        try:
            response = self.client.post("/services/search/jobs", data=params)
        except Exception as exc:
            raise ConnectorFetchError(f"SplunkConnector '{self.name}' get_alert({alert_id}) failed: {exc}") from exc

        if response.status_code >= 400:
            raise ConnectorFetchError(
                f"SplunkConnector '{self.name}' get_alert({alert_id}) failed: HTTP {response.status_code}"
            )

        results = response.json().get("results", [])
        if not results:
            raise ConnectorFetchError(f"SplunkConnector '{self.name}': alert {alert_id} not found")
        return results[0]

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Updates notable event status via Splunk ES's notable_update endpoint.
        Only meaningful for deployments running Enterprise Security — a plain
        Splunk Enterprise install without ES doesn't have this endpoint, so a
        4xx/5xx here is surfaced as ConnectorFetchError rather than assumed
        to mean "not supported" (that distinction requires knowing whether ES
        is installed, which this connector doesn't probe for)."""
        params = {
            "ruleUIDs": alert_id,
            "status": "2",  # Splunk ES status code for "In Progress"; "acknowledged" equivalent
            "output_mode": "json",
        }
        try:
            response = self.client.post("/services/notable_update", data=params)
        except Exception as exc:
            raise ConnectorFetchError(
                f"SplunkConnector '{self.name}' acknowledge_alert({alert_id}) failed: {exc}"
            ) from exc

        if response.status_code >= 400:
            raise ConnectorFetchError(
                f"SplunkConnector '{self.name}' acknowledge_alert({alert_id}) failed: HTTP {response.status_code}"
            )
        return True

    def normalize_event(self, raw: RawAlert) -> CommonAlertSchema:
        urgency_raw = str(raw.get("urgency", "")).lower()
        severity = _URGENCY_MAP.get(urgency_raw, Severity.UNKNOWN)

        time_raw = raw.get("_time")
        timestamp = datetime.fromisoformat(time_raw) if time_raw else datetime.now().astimezone()

        dest_port = raw.get("dest_port")
        src_port = raw.get("src_port")

        return CommonAlertSchema(
            external_alert_id=raw.get("event_id") or raw.get("orig_sid"),
            timestamp=timestamp,
            source=self.name,
            source_product=SourceProduct.SPLUNK,
            severity=severity,
            rule_name=raw.get("signature") or raw.get("search_name"),
            rule_id=raw.get("rule_id") or raw.get("search_name"),
            description=raw.get("description"),
            hostname=raw.get("host") or raw.get("dest"),
            username=raw.get("user"),
            source_ip=raw.get("src_ip") or raw.get("src"),
            destination_ip=raw.get("dest_ip") or raw.get("dest"),
            source_port=int(src_port) if src_port not in (None, "") else None,
            destination_port=int(dest_port) if dest_port not in (None, "") else None,
            protocol=raw.get("transport"),
            process_name=raw.get("process_name"),
            parent_process=raw.get("parent_process_name"),
            command_line=raw.get("process") or raw.get("process_exec"),
            file_hash=raw.get("file_hash"),
            file_name=raw.get("file_name"),
            domain=raw.get("query") or raw.get("dest_dns"),
            url=raw.get("url"),
            cloud_account=raw.get("cloud_account_id") or raw.get("aws_account_id"),
            tags=self._split_tags(raw.get("tag")),
            raw_event=raw,
        )

    @staticmethod
    def _split_tags(tag_field: Any) -> list[str]:
        """Splunk multivalue fields can arrive as a list, a single string, or
        absent entirely — normalize all three into a plain list[str]."""
        if not tag_field:
            return []
        if isinstance(tag_field, list):
            return [str(t) for t in tag_field]
        return [str(tag_field)]
