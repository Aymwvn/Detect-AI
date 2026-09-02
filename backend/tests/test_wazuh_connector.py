"""
Tests for WazuhConnector.

No real Wazuh deployment is reachable from this environment, so these tests
inject a FakeHttpxClient shaped like httpx.Client. Sample documents use
realistic Wazuh alert JSON structure, including the Sysmon-sourced
data.win.eventdata.* nesting Wazuh uses for Windows process events.
"""

from datetime import datetime, timezone

import pytest

from app.schemas import CommonAlertSchema, Severity
from connectors.wazuh import WazuhConnector, _level_to_severity, _parse_sysmon_hashes
from connectors.exceptions import ConnectorAuthError, ConnectorFetchError, NotSupportedError

SAMPLE_WAZUH_ALERT = {
    "timestamp": "2026-08-26T10:31:19.000+0000",
    "agent": {"id": "003", "name": "WIN10-FINANCE-07"},
    "rule": {
        "id": 92050,
        "level": 12,
        "description": "Sysmon - PowerShell encoded command spawned from Office",
        "groups": ["sysmon", "powershell", "office"],
        "mitre": {
            "id": ["T1059.001", "T1566"],
            "technique": ["PowerShell", "Phishing"],
            "tactic": ["Execution", "Initial Access"],
        },
    },
    "data": {
        "srcip": "10.0.0.15",
        "srcport": "51422",
        "dstip": "185.203.0.1",
        "dstport": "443",
        "win": {
            "eventdata": {
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                "commandLine": "powershell.exe -enc SQBFAFgA...",
                "hashes": "MD5=1234ABCD,SHA256=DEADBEEF00112233",
                "user": "FINANCE\\j.doe",
            }
        },
    },
    "full_log": "Sysmon process creation event",
}


class FakeResponse:
    def __init__(self, status_code: int, json_body: dict):
        self.status_code = status_code
        self._json_body = json_body

    def json(self):
        return self._json_body


class FakeHttpxClient:
    def __init__(self, docs: list[dict] | None = None, fail_auth: bool = False):
        self._docs = docs if docs is not None else [SAMPLE_WAZUH_ALERT]
        self._fail_auth = fail_auth
        self.post_calls: list[tuple[str, dict]] = []

    def get(self, path):
        if self._fail_auth:
            return FakeResponse(401, {"error": "unauthorized"})
        return FakeResponse(200, {"cluster_name": "fake-wazuh-indexer"})

    def post(self, path, json=None):
        self.post_calls.append((path, json or {}))
        hits = [{"_id": f"doc-{i}", "_source": doc} for i, doc in enumerate(self._docs)]
        return FakeResponse(200, {"hits": {"hits": hits}})


def make_connector(**client_kwargs) -> tuple[WazuhConnector, FakeHttpxClient]:
    fake_client = FakeHttpxClient(**client_kwargs)
    conn = WazuhConnector(
        connector_id="wazuh-1",
        name="wazuh-prod-1",
        config={"base_url": "https://fake-wazuh:9200", "username": "admin", "password": "pw"},
        client=fake_client,
    )
    return conn, fake_client


# --- level -> severity mapping -------------------------------------------------

@pytest.mark.parametrize(
    "level,expected",
    [
        (0, Severity.INFORMATIONAL),
        (3, Severity.INFORMATIONAL),
        (4, Severity.LOW),
        (6, Severity.LOW),
        (7, Severity.MEDIUM),
        (9, Severity.MEDIUM),
        (10, Severity.HIGH),
        (11, Severity.HIGH),
        (12, Severity.CRITICAL),
        (15, Severity.CRITICAL),
        (None, Severity.UNKNOWN),
        ("not-a-number", Severity.UNKNOWN),
    ],
)
def test_level_to_severity_mapping(level, expected):
    assert _level_to_severity(level) == expected


def test_parse_sysmon_hashes():
    sha256, md5 = _parse_sysmon_hashes("MD5=1234ABCD,SHA256=DEADBEEF00112233")
    assert sha256 == "DEADBEEF00112233"
    assert md5 == "1234ABCD"


def test_parse_sysmon_hashes_missing_field():
    assert _parse_sysmon_hashes(None) == (None, None)
    assert _parse_sysmon_hashes("") == (None, None)


# --- connector behavior -------------------------------------------------

def test_authenticate_success():
    conn, _ = make_connector()
    assert conn.authenticate() is True


def test_authenticate_failure_raises_connector_auth_error():
    conn, _ = make_connector(fail_auth=True)
    with pytest.raises(ConnectorAuthError):
        conn.authenticate()


def test_fetch_alerts_returns_docs_with_id_folded_in():
    conn, fake_client = make_connector()
    alerts = conn.fetch_alerts(since=datetime.now(timezone.utc))
    assert len(alerts) == 1
    assert alerts[0]["_id"] == "doc-0"
    path, body = fake_client.post_calls[0]
    assert path == "/wazuh-alerts-*/_search"
    assert "range" in body["query"]


def test_normalize_event_maps_all_core_fields():
    conn, _ = make_connector()
    raw = {**SAMPLE_WAZUH_ALERT, "_id": "doc-0"}
    normalized = conn.normalize_event(raw)

    assert isinstance(normalized, CommonAlertSchema)
    assert normalized.external_alert_id == "doc-0"
    assert normalized.severity == Severity.CRITICAL.value  # level 12
    assert normalized.rule_name == "Sysmon - PowerShell encoded command spawned from Office"
    assert normalized.rule_id == "92050"
    assert normalized.hostname == "WIN10-FINANCE-07"
    assert normalized.username == "FINANCE\\j.doe"
    assert normalized.source_ip == "10.0.0.15"
    assert normalized.source_port == 51422
    assert normalized.destination_ip == "185.203.0.1"
    assert normalized.destination_port == 443
    assert normalized.process_name.endswith("powershell.exe")
    assert normalized.parent_process.endswith("WINWORD.EXE")
    assert normalized.command_line.startswith("powershell.exe -enc")
    assert normalized.file_hash == "deadbeef00112233"  # prefers sha256 over md5; CAS lowercases hashes
    assert set(normalized.tags) == {"sysmon", "powershell", "office"}
    assert normalized.raw_event == raw


def test_normalize_event_extracts_mitre_mapping():
    conn, _ = make_connector()
    normalized = conn.normalize_event(SAMPLE_WAZUH_ALERT)
    technique_ids = {m.technique_id for m in normalized.existing_mitre_attack_mapping}
    assert technique_ids == {"T1059.001", "T1566"}
    for mapping in normalized.existing_mitre_attack_mapping:
        assert mapping.tactic in {"Execution", "Initial Access"}


def test_normalize_event_handles_missing_optional_fields_gracefully():
    conn, _ = make_connector()
    minimal = {"timestamp": "2026-08-26T10:31:19+00:00", "rule": {"level": 2}}
    normalized = conn.normalize_event(minimal)
    assert normalized.hostname is None
    assert normalized.process_name is None
    assert normalized.file_hash is None
    assert normalized.existing_mitre_attack_mapping == []
    assert normalized.severity == Severity.INFORMATIONAL.value


def test_get_alert_by_id_uses_ids_query():
    conn, fake_client = make_connector()
    raw = conn.get_alert("doc-0")
    assert raw["_id"] == "doc-0"
    _, body = fake_client.post_calls[0]
    assert body["query"]["ids"]["values"] == ["doc-0"]


def test_get_alert_not_found_raises_connector_fetch_error():
    fake_client = FakeHttpxClient(docs=[])
    conn = WazuhConnector(
        connector_id="wazuh-2",
        name="wazuh-empty",
        config={"base_url": "https://fake-wazuh:9200", "username": "admin", "password": "pw"},
        client=fake_client,
    )
    with pytest.raises(ConnectorFetchError):
        conn.get_alert("does-not-exist")


def test_acknowledge_alert_raises_not_supported():
    """Wazuh Indexer alert docs have no workflow-status concept — this
    must raise NotSupportedError, not silently succeed or 500."""
    conn, _ = make_connector()
    with pytest.raises(NotSupportedError) as exc_info:
        conn.acknowledge_alert("doc-0")
    assert exc_info.value.operation == "acknowledge_alert"


def test_missing_base_url_raises_auth_error():
    conn = WazuhConnector(connector_id="w3", name="misconfigured", config={"username": "a", "password": "b"})
    with pytest.raises(ConnectorAuthError):
        _ = conn.client


def test_missing_credentials_raises_auth_error():
    conn = WazuhConnector(connector_id="w4", name="misconfigured", config={"base_url": "https://fake-wazuh:9200"})
    with pytest.raises(ConnectorAuthError):
        _ = conn.client


def test_real_client_builds_successfully_with_valid_config():
    conn = WazuhConnector(
        connector_id="w5",
        name="real-client-test",
        config={"base_url": "https://fake-wazuh:9200", "username": "admin", "password": "pw"},
    )
    client = conn.client
    assert client is not None
    assert type(client).__name__ == "Client"
