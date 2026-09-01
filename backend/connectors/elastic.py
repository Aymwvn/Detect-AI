"""
Elastic Security connector.

Queries the Elastic Security alerts-as-data index (`.alerts-security.alerts-*`)
directly via the Elasticsearch client, rather than the older (deprecated)
Detection Engine signals API. Alert documents follow the Elastic Common
Schema (ECS) plus Kibana's `kibana.alert.*` fields.

Dependency note: the `elasticsearch` package is only imported lazily, inside
_build_client(), so the rest of DetectAI never requires it — a deployment
that doesn't use the Elastic connector shouldn't need to install it. Install
with: pip install elasticsearch>=8,<9 (see connectors/requirements-elastic.txt).

Testing note: pass `client=<your own object>` to __init__ to inject a fake
client (see tests/test_elastic_connector.py) — real integration testing
against a live cluster isn't possible in this environment, so tests verify
against a fake client exposing the same info()/search()/get()/update() shape
elasticsearch-py's client provides.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from app.schemas import CommonAlertSchema, ExistingMitreMapping, Severity, SourceProduct
from connectors.base import RawAlert, SIEMConnector
from connectors.exceptions import ConnectorAuthError, ConnectorFetchError

DEFAULT_ALERTS_INDEX = ".alerts-security.alerts-default"
DEFAULT_PAGE_SIZE = 200

# Elastic's own severity values map 1:1 onto ours — kept as an explicit
# table (not a bare pass-through) so a future Elastic severity change is
# a one-line diff here, not a silent behavior change.
_SEVERITY_MAP = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _dotted_get(raw: dict[str, Any], dotted_path: str, default: Any = None) -> Any:
    """ECS/Kibana fields are stored as nested JSON (e.g. {"host": {"name": ...}}),
    not flat dotted keys, even though their *field names* use dots. This walks
    a dotted path like "kibana.alert.rule.name" through that nesting."""
    return SIEMConnector.safe_get(raw, *dotted_path.split("."), default=default)


class ElasticConnector(SIEMConnector):
    source_product = SourceProduct.ELASTIC_SECURITY.value

    def __init__(
        self,
        connector_id: str,
        name: str,
        config: dict[str, Any] | None = None,
        client: Any | None = None,
    ):
        super().__init__(connector_id, name, config)
        self.index = self.config.get("index", DEFAULT_ALERTS_INDEX)
        self.page_size = int(self.config.get("page_size", DEFAULT_PAGE_SIZE))
        self._client = client  # injected (tests) or lazily built (real use)

    # --- client lifecycle -------------------------------------------------------

    def _build_client(self) -> Any:
        """Builds a real elasticsearch-py client. Not called when a client was
        injected via __init__ (see class docstring). Config is validated
        before the import so a misconfigured connector reports the actual
        problem (missing url) rather than a confusing import error when the
        elasticsearch package also happens not to be installed."""
        es_url = self.config.get("url")
        if not es_url:
            raise ConnectorAuthError(f"ElasticConnector '{self.name}': missing 'url' in config")

        try:
            from elasticsearch import Elasticsearch
        except ImportError as exc:
            raise ConnectorFetchError(
                "The 'elasticsearch' package is required for ElasticConnector. "
                "Install with: pip install elasticsearch>=8,<9"
            ) from exc

        api_key = self.config.get("api_key")
        return Elasticsearch(
            es_url,
            api_key=api_key,
            verify_certs=self.config.get("verify_certs", True),
            request_timeout=self.config.get("timeout_seconds", 30),
        )

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    # --- required interface --------------------------------------------------

    def authenticate(self) -> bool:
        try:
            self.client.info()
        except Exception as exc:  # elasticsearch-py raises its own exception hierarchy
            raise ConnectorAuthError(f"ElasticConnector '{self.name}' auth failed: {exc}") from exc
        return True

    def fetch_alerts(self, since: datetime) -> list[RawAlert]:
        query = {
            "range": {
                "@timestamp": {"gte": since.isoformat()},
            }
        }
        try:
            response = self.client.search(
                index=self.index,
                query=query,
                sort=[{"@timestamp": "asc"}],
                size=self.page_size,
            )
        except Exception as exc:
            raise ConnectorFetchError(f"ElasticConnector '{self.name}' fetch_alerts failed: {exc}") from exc

        hits = response.get("hits", {}).get("hits", [])
        # Fold the ES document id into the payload so normalize_event can use
        # it as external_alert_id without a second round trip.
        return [{**hit.get("_source", {}), "_id": hit.get("_id")} for hit in hits]

    def get_alert(self, alert_id: str) -> RawAlert:
        try:
            response = self.client.get(index=self.index, id=alert_id)
        except Exception as exc:
            raise ConnectorFetchError(
                f"ElasticConnector '{self.name}' get_alert({alert_id}) failed: {exc}"
            ) from exc
        return {**response.get("_source", {}), "_id": response.get("_id")}

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Sets kibana.alert.workflow_status to 'acknowledged' directly on the
        alerts-as-data document. (Elastic Security also exposes a dedicated
        Kibana API for this; querying the index directly avoids requiring a
        second, separately-authenticated Kibana API client for one field.)"""
        try:
            self.client.update(
                index=self.index,
                id=alert_id,
                doc={"kibana": {"alert": {"workflow_status": "acknowledged"}}},
            )
        except Exception as exc:
            raise ConnectorFetchError(
                f"ElasticConnector '{self.name}' acknowledge_alert({alert_id}) failed: {exc}"
            ) from exc
        return True

    def normalize_event(self, raw: RawAlert) -> CommonAlertSchema:
        severity_raw = _dotted_get(raw, "kibana.alert.severity", default="")
        severity = _SEVERITY_MAP.get(str(severity_raw).lower(), Severity.UNKNOWN)

        timestamp_raw = raw.get("@timestamp")
        timestamp = (
            datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
            if timestamp_raw
            else datetime.now().astimezone()
        )

        return CommonAlertSchema(
            external_alert_id=raw.get("_id") or _dotted_get(raw, "kibana.alert.uuid"),
            timestamp=timestamp,
            source=self.name,
            source_product=SourceProduct.ELASTIC_SECURITY,
            severity=severity,
            rule_name=_dotted_get(raw, "kibana.alert.rule.name"),
            rule_id=_dotted_get(raw, "kibana.alert.rule.uuid"),
            description=_dotted_get(raw, "kibana.alert.rule.description"),
            hostname=_dotted_get(raw, "host.name"),
            username=_dotted_get(raw, "user.name"),
            source_ip=_dotted_get(raw, "source.ip"),
            destination_ip=_dotted_get(raw, "destination.ip"),
            source_port=_dotted_get(raw, "source.port"),
            destination_port=_dotted_get(raw, "destination.port"),
            protocol=_dotted_get(raw, "network.transport"),
            process_name=_dotted_get(raw, "process.name"),
            parent_process=_dotted_get(raw, "process.parent.name"),
            command_line=_dotted_get(raw, "process.command_line"),
            file_hash=_dotted_get(raw, "file.hash.sha256") or _dotted_get(raw, "file.hash.md5"),
            file_name=_dotted_get(raw, "file.name"),
            domain=_dotted_get(raw, "dns.question.name") or _dotted_get(raw, "destination.domain"),
            url=_dotted_get(raw, "url.full"),
            cloud_account=_dotted_get(raw, "cloud.account.id"),
            tags=_dotted_get(raw, "kibana.alert.rule.tags", default=[]) or [],
            existing_mitre_attack_mapping=self._extract_mitre_mapping(raw),
            raw_event=raw,
        )

    # --- internal helpers -----------------------------------------------------

    @staticmethod
    def _extract_mitre_mapping(raw: RawAlert) -> list[ExistingMitreMapping]:
        """Elastic Security rules carry MITRE ATT&CK mapping under
        kibana.alert.rule.parameters.threat, following ECS's threat.* shape:
        a list of {tactic: {id, name}, technique: [{id, name, subtechnique: [...]}]}.
        This is the *vendor's own claim* — kept separate from DetectAI's own
        evidence-validated MITRE mapper (Phase 15), per architecture doc §3.
        """
        threat_entries = _dotted_get(raw, "kibana.alert.rule.parameters.threat", default=[]) or []
        mappings: list[ExistingMitreMapping] = []
        for entry in threat_entries:
            tactic = (entry.get("tactic") or {}).get("name")
            for technique in entry.get("technique", []) or []:
                mappings.append(
                    ExistingMitreMapping(
                        technique_id=technique.get("id", "unknown"),
                        technique_name=technique.get("name"),
                        tactic=tactic,
                    )
                )
                # sub-techniques (e.g. T1059.001 under T1059) are listed
                # separately by Elastic — flatten them into the same list.
                for sub in technique.get("subtechnique", []) or []:
                    mappings.append(
                        ExistingMitreMapping(
                            technique_id=sub.get("id", "unknown"),
                            technique_name=sub.get("name"),
                            tactic=tactic,
                        )
                    )
        return mappings
