"""
Tests for ElasticConnector.

No real Elasticsearch cluster is available in this environment, so these
tests inject a FakeElasticsearchClient exposing the same info()/search()/
get()/update() method shapes elasticsearch-py's real client provides. This
verifies DetectAI's own logic (query construction, field mapping, error
handling) — it does not verify elasticsearch-py itself, which is a
separately-maintained, well-tested library.

Sample documents use realistic ECS + kibana.alert.* field shapes based on
Elastic Security's documented alert schema.
"""

from datetime import datetime, timezone

import pytest

from app.schemas import CommonAlertSchema, Severity
from connectors.elastic import ElasticConnector
from connectors.exceptions import ConnectorAuthError, ConnectorFetchError

SAMPLE_ALERT_DOC = {
    "@timestamp": "2026-08-26T10:31:19.000Z",
    "host": {"name": "WIN10-FINANCE-07"},
    "user": {"name": "j.doe"},
    "source": {"ip": "10.0.0.15", "port": 51422},
    "destination": {"ip": "185.203.0.1", "port": 443, "domain": "malicious-c2.example"},
    "network": {"transport": "tcp"},
    "process": {
        "name": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA...",
        "parent": {"name": "winword.exe"},
    },
    "file": {"hash": {"sha256": "ABCDEF0123456789" * 4}, "name": "invoice.doc"},
    "cloud": {"account": {"id": "acct-9911"}},
    "kibana": {
        "alert": {
            "uuid": "kibana-alert-uuid-1",
            "severity": "high",
            "rule": {
                "name": "PowerShell Encoded Command from Office Process",
                "uuid": "rule-uuid-1",
                "description": "Detects Office spawning encoded PowerShell.",
                "tags": ["office", "powershell"],
                "parameters": {
                    "threat": [
                        {
                            "tactic": {"id": "TA0002", "name": "Execution"},
                            "technique": [
                                {
                                    "id": "T1059",
                                    "name": "Command and Scripting Interpreter",
                                    "subtechnique": [{"id": "T1059.001", "name": "PowerShell"}],
                                }
                            ],
                        }
                    ]
                },
            },
        }
    },
}


class FakeElasticsearchClient:
    """Stands in for elasticsearch.Elasticsearch — only implements what
    ElasticConnector actually calls."""

    def __init__(self, docs: list[dict] | None = None, fail_auth: bool = False):
        self._docs = docs if docs is not None else [SAMPLE_ALERT_DOC]
        self._fail_auth = fail_auth
        self.update_calls: list[tuple[str, dict]] = []

    def info(self):
        if self._fail_auth:
            raise RuntimeError("401 Unauthorized")
        return {"cluster_name": "fake-cluster"}

    def search(self, index, query, sort, size):
        hits = [{"_id": f"doc-{i}", "_source": doc} for i, doc in enumerate(self._docs)]
        return {"hits": {"hits": hits}}

    def get(self, index, id):
        if not self._docs:
            raise RuntimeError("404 not found")
        return {"_id": id, "_source": self._docs[0]}

    def update(self, index, id, doc):
        self.update_calls.append((id, doc))
        return {"result": "updated"}


def make_connector(**client_kwargs) -> tuple[ElasticConnector, FakeElasticsearchClient]:
    fake_client = FakeElasticsearchClient(**client_kwargs)
    conn = ElasticConnector(
        connector_id="elastic-1",
        name="elastic-prod-1",
        config={"url": "https://fake-elastic:9200", "api_key": "fake-key"},
        client=fake_client,
    )
    return conn, fake_client


def test_authenticate_success():
    conn, _ = make_connector()
    assert conn.authenticate() is True


def test_authenticate_failure_raises_connector_auth_error():
    conn, _ = make_connector(fail_auth=True)
    with pytest.raises(ConnectorAuthError):
        conn.authenticate()


def test_fetch_alerts_returns_raw_docs_with_id_folded_in():
    conn, _ = make_connector()
    alerts = conn.fetch_alerts(since=datetime.now(timezone.utc))
    assert len(alerts) == 1
    assert alerts[0]["_id"] == "doc-0"
    assert alerts[0]["host"]["name"] == "WIN10-FINANCE-07"


def test_normalize_event_maps_all_core_fields():
    conn, _ = make_connector()
    raw = {**SAMPLE_ALERT_DOC, "_id": "doc-0"}
    normalized = conn.normalize_event(raw)

    assert isinstance(normalized, CommonAlertSchema)
    assert normalized.external_alert_id == "doc-0"
    assert normalized.severity == Severity.HIGH.value
    assert normalized.rule_name == "PowerShell Encoded Command from Office Process"
    assert normalized.rule_id == "rule-uuid-1"
    assert normalized.hostname == "WIN10-FINANCE-07"
    assert normalized.username == "j.doe"
    assert normalized.source_ip == "10.0.0.15"
    assert normalized.destination_ip == "185.203.0.1"
    assert normalized.destination_port == 443
    assert normalized.protocol == "tcp"
    assert normalized.process_name == "powershell.exe"
    assert normalized.parent_process == "winword.exe"
    assert normalized.command_line.startswith("powershell.exe -enc")
    assert normalized.file_name == "invoice.doc"
    assert normalized.domain == "malicious-c2.example"
    assert normalized.cloud_account == "acct-9911"
    assert "office" in normalized.tags
    assert normalized.raw_event == raw


def test_normalize_event_extracts_mitre_mapping_including_subtechnique():
    conn, _ = make_connector()
    raw = {**SAMPLE_ALERT_DOC, "_id": "doc-0"}
    normalized = conn.normalize_event(raw)

    technique_ids = {m.technique_id for m in normalized.existing_mitre_attack_mapping}
    assert "T1059" in technique_ids
    assert "T1059.001" in technique_ids
    for mapping in normalized.existing_mitre_attack_mapping:
        assert mapping.tactic == "Execution"


def test_normalize_event_handles_missing_optional_fields_gracefully():
    conn, _ = make_connector()
    minimal_doc = {
        "@timestamp": "2026-08-26T10:31:19.000Z",
        "kibana": {"alert": {"severity": "low", "rule": {"name": "Minimal Rule"}}},
    }
    normalized = conn.normalize_event(minimal_doc)
    assert normalized.hostname is None
    assert normalized.source_ip is None
    assert normalized.existing_mitre_attack_mapping == []
    assert normalized.severity == Severity.LOW.value


def test_normalize_event_unknown_severity_falls_back():
    conn, _ = make_connector()
    doc = {"@timestamp": "2026-08-26T10:31:19.000Z", "kibana": {"alert": {"severity": "weird-value"}}}
    normalized = conn.normalize_event(doc)
    assert normalized.severity == Severity.UNKNOWN.value


def test_get_alert_by_id():
    conn, _ = make_connector()
    raw = conn.get_alert("doc-0")
    assert raw["_id"] == "doc-0"
    assert raw["host"]["name"] == "WIN10-FINANCE-07"


def test_acknowledge_alert_sends_workflow_status_update():
    conn, fake_client = make_connector()
    result = conn.acknowledge_alert("doc-0")
    assert result is True
    assert len(fake_client.update_calls) == 1
    alert_id, doc = fake_client.update_calls[0]
    assert alert_id == "doc-0"
    assert doc["kibana"]["alert"]["workflow_status"] == "acknowledged"


def test_missing_url_in_config_raises_auth_error_on_real_client_build():
    """No injected client + no url configured -> building a real client
    should fail clearly, not with a confusing AttributeError deep in
    elasticsearch-py."""
    conn = ElasticConnector(connector_id="e2", name="misconfigured", config={})
    with pytest.raises(ConnectorAuthError):
        _ = conn.client


def test_real_client_builds_successfully_with_valid_config():
    """Proves the real elasticsearch-py import + client construction path
    works (no network call — just object construction), not only the
    injected-fake-client path exercised by every other test in this file."""
    conn = ElasticConnector(
        connector_id="e3",
        name="real-client-test",
        config={"url": "https://fake-elastic:9200", "api_key": "fake-key"},
    )
    client = conn.client
    assert client is not None
    assert type(client).__name__ == "Elasticsearch"
