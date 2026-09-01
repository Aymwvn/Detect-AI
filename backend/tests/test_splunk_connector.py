"""
Tests for SplunkConnector.

No real Splunk instance is reachable from this environment, so these tests
inject a FakeHttpxClient shaped like httpx.Client (.get()/.post() returning
objects with .status_code/.json()). Verifies DetectAI's own query
construction, field mapping, and error handling.

Sample result documents use realistic Splunk CIM (Common Information Model)
field names as they'd appear in an Enterprise Security notable-events search.
"""

from datetime import datetime, timezone

import pytest

from app.schemas import CommonAlertSchema, Severity
from connectors.splunk import SplunkConnector
from connectors.exceptions import ConnectorAuthError, ConnectorFetchError

SAMPLE_NOTABLE_EVENT = {
    "event_id": "notable-evt-1",
    "_time": "2026-08-26T10:31:19+00:00",
    "host": "WIN10-FINANCE-07",
    "user": "j.doe",
    "src_ip": "10.0.0.15",
    "src_port": "51422",
    "dest_ip": "185.203.0.1",
    "dest_port": "443",
    "transport": "tcp",
    "process_name": "powershell.exe",
    "parent_process_name": "winword.exe",
    "process": "powershell.exe -enc SQBFAFgA...",
    "file_hash": "abcdef0123456789",
    "file_name": "invoice.doc",
    "query": "malicious-c2.example",
    "urgency": "high",
    "signature": "PowerShell Encoded Command from Office Process",
    "tag": ["office", "powershell"],
}


class FakeResponse:
    def __init__(self, status_code: int, json_body: dict):
        self.status_code = status_code
        self._json_body = json_body

    def json(self):
        return self._json_body


class FakeHttpxClient:
    """Stands in for httpx.Client — only implements what SplunkConnector
    actually calls."""

    def __init__(self, results: list[dict] | None = None, fail_auth: bool = False):
        self._results = results if results is not None else [SAMPLE_NOTABLE_EVENT]
        self._fail_auth = fail_auth
        self.post_calls: list[tuple[str, dict]] = []

    def get(self, path, params=None):
        if self._fail_auth:
            return FakeResponse(401, {"error": "unauthorized"})
        return FakeResponse(200, {"generator": {"build": "test"}})

    def post(self, path, data=None):
        self.post_calls.append((path, data or {}))
        if path == "/services/notable_update":
            return FakeResponse(200, {"success": True})
        return FakeResponse(200, {"results": self._results})


def make_connector(**client_kwargs) -> tuple[SplunkConnector, FakeHttpxClient]:
    fake_client = FakeHttpxClient(**client_kwargs)
    conn = SplunkConnector(
        connector_id="splunk-1",
        name="splunk-prod-1",
        config={"base_url": "https://fake-splunk:8089", "token": "fake-token"},
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


def test_fetch_alerts_returns_results_list():
    conn, fake_client = make_connector()
    alerts = conn.fetch_alerts(since=datetime.now(timezone.utc))
    assert len(alerts) == 1
    assert alerts[0]["event_id"] == "notable-evt-1"
    # verify the oneshot search params were sent correctly
    path, params = fake_client.post_calls[0]
    assert path == "/services/search/jobs"
    assert params["exec_mode"] == "oneshot"
    assert "index=notable" in params["search"]


def test_fetch_alerts_uses_search_override_when_configured():
    fake_client = FakeHttpxClient()
    conn = SplunkConnector(
        connector_id="splunk-2",
        name="splunk-custom",
        config={
            "base_url": "https://fake-splunk:8089",
            "token": "t",
            "search": "search index=custom_alerts sourcetype=my_ids",
        },
        client=fake_client,
    )
    conn.fetch_alerts(since=datetime.now(timezone.utc))
    _, params = fake_client.post_calls[0]
    assert params["search"] == "search index=custom_alerts sourcetype=my_ids"


def test_fetch_alerts_http_error_raises_connector_fetch_error():
    fake_client = FakeHttpxClient()
    fake_client.post = lambda path, data=None: FakeResponse(500, {})
    conn = SplunkConnector(
        connector_id="splunk-3",
        name="splunk-err",
        config={"base_url": "https://fake-splunk:8089"},
        client=fake_client,
    )
    with pytest.raises(ConnectorFetchError):
        conn.fetch_alerts(since=datetime.now(timezone.utc))


def test_normalize_event_maps_all_core_fields():
    conn, _ = make_connector()
    normalized = conn.normalize_event(SAMPLE_NOTABLE_EVENT)

    assert isinstance(normalized, CommonAlertSchema)
    assert normalized.external_alert_id == "notable-evt-1"
    assert normalized.severity == Severity.HIGH.value
    assert normalized.rule_name == "PowerShell Encoded Command from Office Process"
    assert normalized.hostname == "WIN10-FINANCE-07"
    assert normalized.username == "j.doe"
    assert normalized.source_ip == "10.0.0.15"
    assert normalized.source_port == 51422
    assert normalized.destination_ip == "185.203.0.1"
    assert normalized.destination_port == 443
    assert normalized.protocol == "tcp"
    assert normalized.process_name == "powershell.exe"
    assert normalized.parent_process == "winword.exe"
    assert normalized.command_line.startswith("powershell.exe -enc")
    assert normalized.file_hash == "abcdef0123456789"
    assert normalized.domain == "malicious-c2.example"
    assert set(normalized.tags) == {"office", "powershell"}
    assert normalized.raw_event == SAMPLE_NOTABLE_EVENT


def test_normalize_event_handles_missing_optional_fields_gracefully():
    conn, _ = make_connector()
    minimal = {"_time": "2026-08-26T10:31:19+00:00", "urgency": "low"}
    normalized = conn.normalize_event(minimal)
    assert normalized.hostname is None
    assert normalized.source_ip is None
    assert normalized.source_port is None
    assert normalized.tags == []
    assert normalized.severity == Severity.LOW.value


def test_normalize_event_unknown_urgency_falls_back():
    conn, _ = make_connector()
    normalized = conn.normalize_event({"_time": "2026-08-26T10:31:19+00:00", "urgency": "weird"})
    assert normalized.severity == Severity.UNKNOWN.value


def test_normalize_event_single_string_tag_becomes_list():
    conn, _ = make_connector()
    normalized = conn.normalize_event({"_time": "2026-08-26T10:31:19+00:00", "tag": "solo-tag"})
    assert normalized.tags == ["solo-tag"]


def test_get_alert_by_id_builds_correct_search():
    conn, fake_client = make_connector()
    raw = conn.get_alert("notable-evt-1")
    assert raw["event_id"] == "notable-evt-1"
    _, params = fake_client.post_calls[0]
    assert 'event_id="notable-evt-1"' in params["search"]


def test_get_alert_not_found_raises_connector_fetch_error():
    fake_client = FakeHttpxClient(results=[])
    conn = SplunkConnector(
        connector_id="splunk-4",
        name="splunk-empty",
        config={"base_url": "https://fake-splunk:8089"},
        client=fake_client,
    )
    with pytest.raises(ConnectorFetchError):
        conn.get_alert("does-not-exist")


def test_acknowledge_alert_sends_status_update():
    conn, fake_client = make_connector()
    result = conn.acknowledge_alert("notable-evt-1")
    assert result is True
    path, params = fake_client.post_calls[0]
    assert path == "/services/notable_update"
    assert params["ruleUIDs"] == "notable-evt-1"


def test_missing_base_url_raises_auth_error_on_real_client_build():
    conn = SplunkConnector(connector_id="s5", name="misconfigured", config={})
    with pytest.raises(ConnectorAuthError):
        _ = conn.client


def test_real_client_builds_successfully_with_valid_config():
    """Proves the real httpx import + client construction path works, not
    only the injected-fake-client path exercised by every other test."""
    conn = SplunkConnector(
        connector_id="s6",
        name="real-client-test",
        config={"base_url": "https://fake-splunk:8089", "token": "fake-token"},
    )
    client = conn.client
    assert client is not None
    assert type(client).__name__ == "Client"
