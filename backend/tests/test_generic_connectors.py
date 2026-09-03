"""
Tests for GenericWebhookConnector and GenericRESTConnector.
"""

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any

import pytest

from app.schemas import CommonAlertSchema, Severity, SourceProduct
from connectors.generic import (
    GenericRESTConnector,
    GenericWebhookConnector,
    _normalize_severity,
    _normalize_tags,
    _normalize_timestamp,
    normalize_generic_alert,
)
from connectors.exceptions import ConnectorAuthError, ConnectorFetchError, NotSupportedError

# --- severity normalization -------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        ("low", Severity.LOW),
        ("HIGH", Severity.HIGH),
        ("Critical", Severity.CRITICAL),
        ("warning", Severity.MEDIUM),
        ("info", Severity.INFORMATIONAL),
        ("gibberish", Severity.UNKNOWN),
        (None, Severity.UNKNOWN),
    ],
)
def test_normalize_severity_strings(value, expected):
    assert _normalize_severity(value) == expected


@pytest.mark.parametrize(
    "value,severity_max,expected",
    [
        (1, 10, Severity.LOW),      # ratio 0.10 -> LOW
        (4, 10, Severity.MEDIUM),   # ratio 0.40 -> MEDIUM
        (7, 10, Severity.HIGH),     # ratio 0.70 -> HIGH
        (10, 10, Severity.CRITICAL),  # ratio 1.00 -> CRITICAL
        (0, 10, Severity.LOW),      # ratio 0.00 -> LOW
    ],
)
def test_normalize_severity_numeric(value, severity_max, expected):
    assert _normalize_severity(value, severity_max=severity_max) == expected


def test_normalize_severity_unparseable_value_falls_back():
    assert _normalize_severity("totally-unrecognized-string") == Severity.UNKNOWN
    assert _normalize_severity(object()) == Severity.UNKNOWN


# --- timestamp normalization -------------------------------------------------

def test_normalize_timestamp_iso_string():
    ts = _normalize_timestamp("2026-08-26T10:31:19Z")
    assert ts.year == 2026 and ts.month == 8 and ts.day == 26


def test_normalize_timestamp_unix_seconds():
    ts = _normalize_timestamp(1798000000)  # seconds-scale epoch
    assert ts.year >= 2026


def test_normalize_timestamp_unix_millis():
    ts = _normalize_timestamp(1798000000000)  # millis-scale epoch
    assert ts.year >= 2026


def test_normalize_timestamp_none_defaults_to_now():
    ts = _normalize_timestamp(None)
    assert (datetime.now().astimezone() - ts).total_seconds() < 5


def test_normalize_timestamp_garbage_string_defaults_to_now():
    ts = _normalize_timestamp("not a date")
    assert (datetime.now().astimezone() - ts).total_seconds() < 5


# --- tags normalization -------------------------------------------------

def test_normalize_tags_list():
    assert _normalize_tags(["a", "b"]) == ["a", "b"]


def test_normalize_tags_comma_string():
    assert _normalize_tags("a, b,c") == ["a", "b", "c"]


def test_normalize_tags_empty():
    assert _normalize_tags(None) == []
    assert _normalize_tags("") == []


# --- shared normalize_generic_alert, field-alias flexibility -------------------

def test_normalize_generic_alert_with_standard_field_names():
    raw = {
        "id": "evt-1",
        "timestamp": "2026-08-26T10:31:19Z",
        "severity": "high",
        "rule_name": "Suspicious PowerShell",
        "hostname": "WIN10-FINANCE-07",
        "source_ip": "10.0.0.15",
        "process_name": "powershell.exe",
        "tags": ["custom", "test"],
    }
    normalized = normalize_generic_alert(raw, "custom-source", SourceProduct.GENERIC_WEBHOOK)
    assert isinstance(normalized, CommonAlertSchema)
    assert normalized.external_alert_id == "evt-1"
    assert normalized.severity == Severity.HIGH.value
    assert normalized.hostname == "WIN10-FINANCE-07"
    assert normalized.source_ip == "10.0.0.15"
    assert set(normalized.tags) == {"custom", "test"}


def test_normalize_generic_alert_with_alias_field_names():
    """Different vendor, different key names for the same concepts —
    this is the whole point of the alias system."""
    raw = {
        "event_id": "evt-2",
        "@timestamp": "2026-08-26T10:31:19Z",
        "level": "critical",
        "signature": "Malware Detected",
        "host_name": "SRV-01",
        "srcip": "10.0.0.99",
        "image": "malware.exe",
    }
    normalized = normalize_generic_alert(raw, "another-source", SourceProduct.GENERIC_REST)
    assert normalized.external_alert_id == "evt-2"
    assert normalized.severity == Severity.CRITICAL.value
    assert normalized.rule_name == "Malware Detected"
    assert normalized.hostname == "SRV-01"
    assert normalized.source_ip == "10.0.0.99"
    assert normalized.process_name == "malware.exe"


def test_normalize_generic_alert_case_insensitive_keys():
    raw = {"HOSTNAME": "CASE-TEST", "Severity": "low"}
    normalized = normalize_generic_alert(raw, "s", SourceProduct.GENERIC_WEBHOOK)
    assert normalized.hostname == "CASE-TEST"
    assert normalized.severity == Severity.LOW.value


def test_normalize_generic_alert_missing_everything_still_produces_valid_schema():
    normalized = normalize_generic_alert({}, "empty-source", SourceProduct.GENERIC_WEBHOOK)
    assert normalized.hostname is None
    assert normalized.severity == Severity.UNKNOWN.value
    assert normalized.raw_event == {}


def test_normalize_generic_alert_custom_field_aliases_override():
    custom_aliases = {"hostname": ["machine"]}
    raw = {"machine": "CUSTOM-HOST"}
    normalized = normalize_generic_alert(
        raw, "s", SourceProduct.GENERIC_WEBHOOK, field_aliases=custom_aliases
    )
    assert normalized.hostname == "CUSTOM-HOST"


# --- GenericWebhookConnector -------------------------------------------------

def make_webhook_connector(**config_overrides) -> GenericWebhookConnector:
    config = {"shared_secret": "test-secret"}
    config.update(config_overrides)
    return GenericWebhookConnector(connector_id="wh-1", name="my-webhook", config=config)


def test_webhook_authenticate_success_with_secret():
    conn = make_webhook_connector()
    assert conn.authenticate() is True


def test_webhook_authenticate_fails_without_secret():
    conn = GenericWebhookConnector(connector_id="wh-2", name="unconfigured", config={})
    with pytest.raises(ConnectorAuthError):
        conn.authenticate()


def test_webhook_fetch_alerts_not_supported():
    conn = make_webhook_connector()
    with pytest.raises(NotSupportedError) as exc_info:
        conn.fetch_alerts(since=datetime.now(timezone.utc))
    assert exc_info.value.operation == "fetch_alerts"


def test_webhook_normalize_event():
    conn = make_webhook_connector()
    raw = {"hostname": "WEBHOOK-HOST", "severity": "high"}
    normalized = conn.normalize_event(raw)
    assert normalized.hostname == "WEBHOOK-HOST"
    assert normalized.source == "my-webhook"
    assert normalized.source_product == SourceProduct.GENERIC_WEBHOOK.value


def test_webhook_verify_signature_valid():
    conn = make_webhook_connector()
    payload = b'{"hostname": "test"}'
    expected_sig = hmac.new(b"test-secret", payload, hashlib.sha256).hexdigest()
    assert conn.verify_signature(payload, expected_sig) is True


def test_webhook_verify_signature_invalid():
    conn = make_webhook_connector()
    payload = b'{"hostname": "test"}'
    assert conn.verify_signature(payload, "wrong-signature") is False


def test_webhook_verify_signature_tampered_payload():
    """The classic webhook security check: signature was computed over
    the original payload, but the request body has since been altered —
    must fail."""
    conn = make_webhook_connector()
    original_payload = b'{"hostname": "test", "severity": "low"}'
    tampered_payload = b'{"hostname": "test", "severity": "critical"}'
    sig_for_original = hmac.new(b"test-secret", original_payload, hashlib.sha256).hexdigest()
    assert conn.verify_signature(tampered_payload, sig_for_original) is False


def test_webhook_verify_signature_no_secret_configured_fails_closed():
    conn = GenericWebhookConnector(connector_id="wh-3", name="no-secret", config={})
    assert conn.verify_signature(b"anything", "any-sig") is False


def test_webhook_verify_signature_missing_header_fails_closed():
    conn = make_webhook_connector()
    assert conn.verify_signature(b"anything", None) is False


# --- GenericRESTConnector -------------------------------------------------

class FakeResponse:
    def __init__(self, status_code: int, json_body: Any):
        self.status_code = status_code
        self._json_body = json_body

    def json(self):
        return self._json_body


class FakeHttpxClient:
    def __init__(self, body: Any = None, status_code: int = 200, fail_auth: bool = False):
        self._body = body if body is not None else {"results": []}
        self._status_code = status_code
        self._fail_auth = fail_auth
        self.get_calls: list[tuple[str, dict]] = []

    def get(self, path, params=None):
        self.get_calls.append((path, params or {}))
        if path in ("/", "/health") and self._fail_auth:
            return FakeResponse(401, {})
        if path in ("/", "/health"):
            return FakeResponse(200, {"status": "ok"})
        return FakeResponse(self._status_code, self._body)


def make_rest_connector(body=None, status_code=200, fail_auth=False, **config_overrides) -> tuple:
    fake_client = FakeHttpxClient(body=body, status_code=status_code, fail_auth=fail_auth)
    config = {"base_url": "https://fake-source.example"}
    config.update(config_overrides)
    conn = GenericRESTConnector(connector_id="rest-1", name="my-rest-source", config=config, client=fake_client)
    return conn, fake_client


def test_rest_authenticate_success():
    conn, _ = make_rest_connector()
    assert conn.authenticate() is True


def test_rest_authenticate_failure():
    conn, _ = make_rest_connector(fail_auth=True)
    with pytest.raises(ConnectorAuthError):
        conn.authenticate()


def test_rest_fetch_alerts_plain_list_response():
    conn, _ = make_rest_connector(body=[{"hostname": "h1"}, {"hostname": "h2"}])
    alerts = conn.fetch_alerts(since=datetime.now(timezone.utc))
    assert len(alerts) == 2


def test_rest_fetch_alerts_results_key_autodetect():
    conn, _ = make_rest_connector(body={"alerts": [{"hostname": "h1"}]})
    alerts = conn.fetch_alerts(since=datetime.now(timezone.utc))
    assert len(alerts) == 1
    assert alerts[0]["hostname"] == "h1"


def test_rest_fetch_alerts_custom_results_key():
    conn, _ = make_rest_connector(body={"my_custom_wrapper": [{"hostname": "h1"}]}, results_key="my_custom_wrapper")
    alerts = conn.fetch_alerts(since=datetime.now(timezone.utc))
    assert len(alerts) == 1


def test_rest_fetch_alerts_unrecognized_shape_raises():
    conn, _ = make_rest_connector(body={"totally_unexpected_key": []})
    with pytest.raises(ConnectorFetchError):
        conn.fetch_alerts(since=datetime.now(timezone.utc))


def test_rest_fetch_alerts_http_error_raises():
    conn, _ = make_rest_connector(status_code=500, body={})
    with pytest.raises(ConnectorFetchError):
        conn.fetch_alerts(since=datetime.now(timezone.utc))


def test_rest_normalize_event():
    conn, _ = make_rest_connector()
    normalized = conn.normalize_event({"hostname": "REST-HOST", "severity": "medium"})
    assert normalized.hostname == "REST-HOST"
    assert normalized.source_product == SourceProduct.GENERIC_REST.value


def test_rest_missing_base_url_raises_auth_error():
    conn = GenericRESTConnector(connector_id="r2", name="misconfigured", config={})
    with pytest.raises(ConnectorAuthError):
        _ = conn.client


def test_rest_real_client_builds_with_api_key():
    conn = GenericRESTConnector(
        connector_id="r3",
        name="real-client-test",
        config={"base_url": "https://fake-source.example", "api_key": "secret-key"},
    )
    client = conn.client
    assert client is not None
    assert type(client).__name__ == "Client"
