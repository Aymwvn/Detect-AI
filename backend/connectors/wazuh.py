"""
Wazuh connector.

Wazuh alerts live in the Wazuh Indexer (an OpenSearch fork), not the Wazuh
Manager's own REST API (which handles agent/rule/manager management, not
alert search). This connector queries the indexer's `wazuh-alerts-*` index
pattern directly over its OpenSearch-compatible HTTP API.

Uses httpx (already a project dependency, see connectors/splunk.py for the
same rationale) with HTTP basic auth, which is the indexer's default auth
mode in most Wazuh deployments.

Field mapping note: Wazuh's alert schema is its own JSON structure (not
ECS). Windows/Sysmon-sourced alerts nest process/network detail under
`data.win.eventdata.*`, which is what this connector maps by default since
it's the most common source of the kind of process-chain alerts DetectAI
cares about. Alerts from other decoders (e.g. auditd, PAM, firewall
decoders) populate different `data.*` fields — connector authors extending
Wazuh coverage further should add decoder-specific mapping branches rather
than assuming every alert is a Sysmon event.

Testing note: pass `client=<your own object>` to __init__ to inject a fake
HTTP client (see tests/test_wazuh_connector.py) — no real Wazuh deployment
is reachable from this environment.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.schemas import CommonAlertSchema, ExistingMitreMapping, Severity, SourceProduct
from connectors.base import RawAlert, SIEMConnector
from connectors.exceptions import ConnectorAuthError, ConnectorFetchError, NotSupportedError

DEFAULT_INDEX_PATTERN = "wazuh-alerts-*"
DEFAULT_PAGE_SIZE = 200


def _dotted_get(raw: dict[str, Any], dotted_path: str, default: Any = None) -> Any:
    return SIEMConnector.safe_get(raw, *dotted_path.split("."), default=default)


def _level_to_severity(level: Any) -> Severity:
    """Wazuh rule levels run 0-15. There's no single official level->severity
    cutover, but this follows Wazuh's own documented rule-of-thumb grouping
    (0-3 informational/low noise, 4-6 low-to-medium, 7-11 actionable
    medium-to-high, 12+ critical). Deployments with heavily customized rule
    levels can override this via a connector config option in a future pass
    if needed — not required for MVP."""
    try:
        level_int = int(level)
    except (TypeError, ValueError):
        return Severity.UNKNOWN

    if level_int <= 3:
        return Severity.INFORMATIONAL
    if level_int <= 6:
        return Severity.LOW
    if level_int <= 9:
        return Severity.MEDIUM
    if level_int <= 11:
        return Severity.HIGH
    return Severity.CRITICAL


def _parse_sysmon_hashes(hashes_field: Any) -> tuple[str | None, str | None]:
    """Sysmon's hashes field arrives as a single string like
    "MD5=ABCD...,SHA256=1234...". Returns (sha256, md5), preferring sha256
    as the canonical hash CommonAlertSchema stores."""
    if not hashes_field or not isinstance(hashes_field, str):
        return None, None
    parts = dict(p.split("=", 1) for p in hashes_field.split(",") if "=" in p)
    return parts.get("SHA256"), parts.get("MD5")


class WazuhConnector(SIEMConnector):
    source_product = SourceProduct.WAZUH.value

    def __init__(
        self,
        connector_id: str,
        name: str,
        config: dict[str, Any] | None = None,
        client: Any | None = None,
    ):
        super().__init__(connector_id, name, config)
        self.index_pattern = self.config.get("index_pattern", DEFAULT_INDEX_PATTERN)
        self.page_size = int(self.config.get("page_size", DEFAULT_PAGE_SIZE))
        self._client = client

    # --- client lifecycle -------------------------------------------------------

    def _build_client(self) -> Any:
        base_url = self.config.get("base_url")
        if not base_url:
            raise ConnectorAuthError(f"WazuhConnector '{self.name}': missing 'base_url' in config")

        username = self.config.get("username")
        password = self.config.get("password")
        if not username or not password:
            raise ConnectorAuthError(
                f"WazuhConnector '{self.name}': 'username' and 'password' are required in config"
            )

        try:
            import httpx
        except ImportError as exc:
            raise ConnectorFetchError(
                "The 'httpx' package is required for WazuhConnector. Install with: pip install httpx"
            ) from exc

        return httpx.Client(
            base_url=base_url,
            auth=(username, password),
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
            response = self.client.get("/")
        except Exception as exc:
            raise ConnectorAuthError(f"WazuhConnector '{self.name}' auth failed: {exc}") from exc

        if response.status_code == 401:
            raise ConnectorAuthError(f"WazuhConnector '{self.name}': invalid credentials")
        if response.status_code >= 400:
            raise ConnectorAuthError(f"WazuhConnector '{self.name}' auth failed: HTTP {response.status_code}")
        return True

    def fetch_alerts(self, since: datetime) -> list[RawAlert]:
        body = {
            "query": {"range": {"timestamp": {"gte": since.isoformat()}}},
            "sort": [{"timestamp": "asc"}],
            "size": self.page_size,
        }
        try:
            response = self.client.post(f"/{self.index_pattern}/_search", json=body)
        except Exception as exc:
            raise ConnectorFetchError(f"WazuhConnector '{self.name}' fetch_alerts failed: {exc}") from exc

        if response.status_code >= 400:
            raise ConnectorFetchError(
                f"WazuhConnector '{self.name}' fetch_alerts failed: HTTP {response.status_code}"
            )

        hits = response.json().get("hits", {}).get("hits", [])
        return [{**hit.get("_source", {}), "_id": hit.get("_id")} for hit in hits]

    def get_alert(self, alert_id: str) -> RawAlert:
        body = {"query": {"ids": {"values": [alert_id]}}}
        try:
            response = self.client.post(f"/{self.index_pattern}/_search", json=body)
        except Exception as exc:
            raise ConnectorFetchError(f"WazuhConnector '{self.name}' get_alert({alert_id}) failed: {exc}") from exc

        if response.status_code >= 400:
            raise ConnectorFetchError(
                f"WazuhConnector '{self.name}' get_alert({alert_id}) failed: HTTP {response.status_code}"
            )

        hits = response.json().get("hits", {}).get("hits", [])
        if not hits:
            raise ConnectorFetchError(f"WazuhConnector '{self.name}': alert {alert_id} not found")
        hit = hits[0]
        return {**hit.get("_source", {}), "_id": hit.get("_id")}

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Wazuh Indexer alert documents are immutable log records, not a
        workflow-tracked alert object like Elastic Security's alerts-as-data
        or Splunk ES's notable events — there's no standard "acknowledge"
        concept to update. Explicitly unsupported rather than faking it."""
        raise NotSupportedError("acknowledge_alert", self.name)

    def normalize_event(self, raw: RawAlert) -> CommonAlertSchema:
        severity = _level_to_severity(_dotted_get(raw, "rule.level"))

        timestamp_raw = raw.get("timestamp")
        timestamp = datetime.fromisoformat(timestamp_raw) if timestamp_raw else datetime.now().astimezone()

        sha256, md5 = _parse_sysmon_hashes(_dotted_get(raw, "data.win.eventdata.hashes"))

        dest_port = _dotted_get(raw, "data.dstport")
        src_port = _dotted_get(raw, "data.srcport")

        return CommonAlertSchema(
            external_alert_id=raw.get("_id") or _dotted_get(raw, "id"),
            timestamp=timestamp,
            source=self.name,
            source_product=SourceProduct.WAZUH,
            severity=severity,
            rule_name=_dotted_get(raw, "rule.description"),
            rule_id=str(_dotted_get(raw, "rule.id")) if _dotted_get(raw, "rule.id") is not None else None,
            description=_dotted_get(raw, "full_log"),
            hostname=_dotted_get(raw, "agent.name"),
            username=_dotted_get(raw, "data.win.eventdata.user") or _dotted_get(raw, "data.srcuser"),
            source_ip=_dotted_get(raw, "data.srcip"),
            destination_ip=_dotted_get(raw, "data.dstip"),
            source_port=int(src_port) if src_port not in (None, "") else None,
            destination_port=int(dest_port) if dest_port not in (None, "") else None,
            process_name=_dotted_get(raw, "data.win.eventdata.image"),
            parent_process=_dotted_get(raw, "data.win.eventdata.parentImage"),
            command_line=_dotted_get(raw, "data.win.eventdata.commandLine"),
            file_hash=sha256 or md5,
            file_name=_dotted_get(raw, "syscheck.path"),
            tags=_dotted_get(raw, "rule.groups", default=[]) or [],
            existing_mitre_attack_mapping=self._extract_mitre_mapping(raw),
            raw_event=raw,
        )

    @staticmethod
    def _extract_mitre_mapping(raw: RawAlert) -> list[ExistingMitreMapping]:
        """Wazuh's MITRE integration provides three parallel lists under
        rule.mitre: id, technique, tactic. Zipped together here — a
        mismatched-length response (malformed source data) is handled by
        zip() truncating to the shortest list rather than raising."""
        ids = _dotted_get(raw, "rule.mitre.id", default=[]) or []
        techniques = _dotted_get(raw, "rule.mitre.technique", default=[]) or []
        tactics = _dotted_get(raw, "rule.mitre.tactic", default=[]) or []

        mappings: list[ExistingMitreMapping] = []
        for i, technique_id in enumerate(ids):
            mappings.append(
                ExistingMitreMapping(
                    technique_id=technique_id,
                    technique_name=techniques[i] if i < len(techniques) else None,
                    tactic=tactics[i] if i < len(tactics) else None,
                )
            )
        return mappings
