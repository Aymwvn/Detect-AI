"""
Tests for the SIEMConnector abstract interface.

Uses a small in-memory MockConnector to prove the contract works end to
end, without needing a real SIEM, network access, or the ingestion
pipeline (Phase 10) to exist yet.
"""

from datetime import datetime, timezone

import pytest

from app.schemas import CommonAlertSchema, SourceProduct
from connectors.base import RawAlert, SIEMConnector
from connectors.exceptions import ConnectorAuthError, NotSupportedError


class MockConnector(SIEMConnector):
    """A minimal, fully working connector used only for tests — proves the
    abstract interface can be implemented and behaves as documented."""

    source_product = SourceProduct.GENERIC_WEBHOOK.value

    def __init__(self, *args, fail_auth: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self._fail_auth = fail_auth
        self._fake_alerts: list[RawAlert] = [
            {
                "id": "vendor-alert-1",
                "detected_at": "2026-08-26T10:31:19Z",
                "host": {"name": "WIN10-FINANCE-07"},
                "process": {"name": "powershell.exe", "parent": {"name": "winword.exe"}},
                "severity": "high",
            }
        ]

    def authenticate(self) -> bool:
        if self._fail_auth:
            raise ConnectorAuthError("invalid API key")
        return True

    def fetch_alerts(self, since: datetime) -> list[RawAlert]:
        return self._fake_alerts

    def normalize_event(self, raw: RawAlert) -> CommonAlertSchema:
        return CommonAlertSchema(
            external_alert_id=self.safe_get(raw, "id"),
            timestamp=datetime.fromisoformat(raw["detected_at"].replace("Z", "+00:00")),
            source=self.name,
            source_product=SourceProduct.GENERIC_WEBHOOK,
            severity=self.safe_get(raw, "severity", default="unknown"),
            hostname=self.safe_get(raw, "host", "name"),
            process_name=self.safe_get(raw, "process", "name"),
            parent_process=self.safe_get(raw, "process", "parent", "name"),
            # a field the mock payload doesn't provide at all — must gracefully be None
            destination_ip=self.safe_get(raw, "network", "destination", "ip"),
            raw_event=raw,
        )


def make_connector(**kwargs) -> MockConnector:
    return MockConnector(connector_id="test-1", name="mock-source", config={}, **kwargs)


def test_authenticate_success():
    conn = make_connector()
    assert conn.authenticate() is True


def test_authenticate_failure_raises_auth_error():
    conn = make_connector(fail_auth=True)
    with pytest.raises(ConnectorAuthError):
        conn.authenticate()


def test_fetch_and_normalize_end_to_end():
    conn = make_connector()
    raw_alerts = conn.fetch_alerts(since=datetime.now(timezone.utc))
    assert len(raw_alerts) == 1

    normalized = conn.normalize_event(raw_alerts[0])
    assert isinstance(normalized, CommonAlertSchema)
    assert normalized.hostname == "WIN10-FINANCE-07"
    assert normalized.process_name == "powershell.exe"
    assert normalized.parent_process == "winword.exe"
    # raw_event must preserve the untouched original payload
    assert normalized.raw_event == raw_alerts[0]


def test_missing_nested_field_defaults_to_none_not_keyerror():
    """The whole point of safe_get: a source that doesn't provide network
    context shouldn't blow up normalization."""
    conn = make_connector()
    raw_alerts = conn.fetch_alerts(since=datetime.now(timezone.utc))
    normalized = conn.normalize_event(raw_alerts[0])
    assert normalized.destination_ip is None


def test_unimplemented_get_alert_raises_not_supported():
    conn = make_connector()
    with pytest.raises(NotSupportedError) as exc_info:
        conn.get_alert("some-id")
    assert exc_info.value.operation == "get_alert"
    assert exc_info.value.connector_name == "mock-source"


def test_unimplemented_acknowledge_alert_raises_not_supported():
    conn = make_connector()
    with pytest.raises(NotSupportedError):
        conn.acknowledge_alert("some-id")


def test_cannot_instantiate_abstract_base_directly():
    with pytest.raises(TypeError):
        SIEMConnector(connector_id="x", name="x")  # type: ignore[abstract]


def test_safe_get_helper_various_paths():
    raw = {"a": {"b": {"c": 42}}}
    assert SIEMConnector.safe_get(raw, "a", "b", "c") == 42
    assert SIEMConnector.safe_get(raw, "a", "x", "c") is None
    assert SIEMConnector.safe_get(raw, "a", "x", "c", default="fallback") == "fallback"
    assert SIEMConnector.safe_get({}, "anything") is None
