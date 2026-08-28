"""
Tests for the Common Alert Schema.

Run with:  pytest backend/tests/test_common_alert_schema.py -v
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.common_alert_schema import (
    AlertStatus,
    CommonAlertSchema,
    Severity,
    SourceProduct,
)


def test_minimal_alert_with_only_required_fields():
    """A source that only gives us the bare minimum should still normalize cleanly."""
    alert = CommonAlertSchema(
        timestamp=datetime.now(timezone.utc),
        source="test-source-1",
        source_product=SourceProduct.GENERIC_WEBHOOK,
    )
    assert alert.severity == Severity.UNKNOWN
    assert alert.status == AlertStatus.NEW
    assert alert.hostname is None
    assert alert.raw_event == {}
    assert alert.tags == []


def test_full_powershell_alert_example():
    """The Office -> PowerShell -> network chain example from the architecture doc."""
    alert = CommonAlertSchema(
        external_alert_id="elastic-alert-88213",
        timestamp=datetime(2026, 8, 26, 10, 31, 19),
        source="elastic-prod-1",
        source_product=SourceProduct.ELASTIC_SECURITY,
        severity=Severity.HIGH,
        rule_name="PowerShell Encoded Command from Office Process",
        hostname="WIN10-FINANCE-07",
        username="j.doe",
        process_name="powershell.exe",
        parent_process="winword.exe",
        command_line="powershell.exe -enc SQBFAFgA...",
        destination_ip="185.203.0.1",
        destination_port=443,
        protocol="tcp",
        tags=["office", "powershell", "encoded-command"],
    )
    assert alert.has_process_context() is True
    assert alert.has_network_context() is True
    assert alert.entity_keys()["hostname"] == "WIN10-FINANCE-07"


def test_invalid_port_rejected():
    with pytest.raises(ValidationError):
        CommonAlertSchema(
            timestamp=datetime.now(timezone.utc),
            source="test-source-1",
            source_product=SourceProduct.GENERIC_WEBHOOK,
            destination_port=99999,  # out of range
        )


def test_file_hash_normalized_to_lowercase():
    alert = CommonAlertSchema(
        timestamp=datetime.now(timezone.utc),
        source="test-source-1",
        source_product=SourceProduct.GENERIC_WEBHOOK,
        file_hash="ABC123DEF456",
    )
    assert alert.file_hash == "abc123def456"


def test_missing_required_fields_raises():
    """timestamp, source, and source_product are the only truly required fields —
    everything else must gracefully default, per architecture doc section 3."""
    with pytest.raises(ValidationError):
        CommonAlertSchema(source="test-source-1", source_product=SourceProduct.GENERIC_WEBHOOK)


def test_alert_id_auto_generated_and_unique():
    a1 = CommonAlertSchema(
        timestamp=datetime.now(timezone.utc), source="s1", source_product=SourceProduct.GENERIC_WEBHOOK
    )
    a2 = CommonAlertSchema(
        timestamp=datetime.now(timezone.utc), source="s1", source_product=SourceProduct.GENERIC_WEBHOOK
    )
    assert a1.alert_id != a2.alert_id
