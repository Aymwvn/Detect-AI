"""
Common Alert Schema (CAS)
=========================

The vendor-neutral, normalized representation of a security alert that every
connector (Elastic, Splunk, Wazuh, Sentinel, webhook, syslog, ...) maps its
raw output into. Nothing downstream of ingestion — dedup, correlation, risk
scoring, AI analysis, MITRE mapping — should ever touch a vendor-specific
field directly. It only ever sees a CommonAlertSchema.

Design rules (see docs/ARCHITECTURE.md, sections 3 and 12):
- No field is assumed to be present. Every SIEM provides a different subset.
- Missing data is `None`, never guessed, never fabricated.
- `raw_event` always preserves the original vendor payload, so nothing is
  lost in translation and analysts can always inspect the source truth.
- This is a Pydantic model so it doubles as runtime validation: a connector
  that produces a malformed alert fails loudly at ingestion, not silently
  three layers downstream.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Normalized severity, independent of each vendor's own scale."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class SourceProduct(str, Enum):
    """Which connector/product produced this alert. Extend as connectors are added."""
    ELASTIC_SECURITY = "elastic_security"
    SPLUNK = "splunk"
    WAZUH = "wazuh"
    MICROSOFT_SENTINEL = "microsoft_sentinel"
    GENERIC_WEBHOOK = "generic_webhook"
    GENERIC_REST = "generic_rest"
    SYSLOG_CEF = "syslog_cef"
    SYSLOG_LEEF = "syslog_leef"
    OTHER = "other"


class AlertStatus(str, Enum):
    """Lifecycle status inside DetectAI, not the vendor's own status field."""
    NEW = "new"
    ENRICHED = "enriched"        # normalized + rule score computed
    ANALYZED = "analyzed"        # AI analysis attached
    UNDER_INVESTIGATION = "under_investigation"
    RESOLVED = "resolved"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Supporting sub-models
# ---------------------------------------------------------------------------

class AuthenticationContext(BaseModel):
    """Optional auth-related context, populated when the source alert is auth-related."""
    auth_method: Optional[str] = None          # e.g. "password", "mfa", "sso", "kerberos"
    success: Optional[bool] = None
    source_geo: Optional[str] = None            # country/region if resolvable
    failed_attempt_count: Optional[int] = None
    is_impossible_travel: Optional[bool] = None


class ExistingMitreMapping(BaseModel):
    """MITRE mapping the *source SIEM itself* already provided, if any.

    This is distinct from DetectAI's own evidence-validated MITRE mapper
    (see services/mitre/). We keep the vendor's original claim separately
    so the two can be compared instead of silently merged.
    """
    technique_id: str
    technique_name: Optional[str] = None
    tactic: Optional[str] = None


# ---------------------------------------------------------------------------
# Common Alert Schema
# ---------------------------------------------------------------------------

class CommonAlertSchema(BaseModel):
    # --- identity & provenance --------------------------------------------------
    alert_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="DetectAI-internal unique ID. Distinct from the vendor's own alert ID.",
    )
    external_alert_id: Optional[str] = Field(
        default=None, description="The alert ID as issued by the source SIEM, if any."
    )
    timestamp: datetime = Field(..., description="When the underlying event/detection occurred.")
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    source: str = Field(..., description="Free-text/short identifier of the specific source instance, e.g. 'elastic-prod-1'.")
    source_product: SourceProduct

    # --- classification ------------------------------------------------------
    severity: Severity = Severity.UNKNOWN
    rule_name: Optional[str] = None
    rule_id: Optional[str] = None
    description: Optional[str] = None

    # --- host / identity -------------------------------------------------------
    hostname: Optional[str] = None
    username: Optional[str] = None

    # --- network -----------------------------------------------------------
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[Protocol] = None

    # --- process -----------------------------------------------------------
    process_name: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None

    # --- file / artifact -----------------------------------------------------
    file_hash: Optional[str] = None
    file_name: Optional[str] = None

    # --- web / dns -----------------------------------------------------------
    domain: Optional[str] = None
    url: Optional[str] = None

    # --- cloud / identity context -----------------------------------------------
    cloud_account: Optional[str] = None
    authentication_context: Optional[AuthenticationContext] = None

    # --- correlation & context -------------------------------------------------
    raw_event: dict[str, Any] = Field(
        default_factory=dict,
        description="The original, untouched vendor payload. Always preserved for analyst inspection.",
    )
    related_events: list[str] = Field(
        default_factory=list,
        description="alert_id/event_id values this alert is already known to relate to (populated by the correlation engine, not the connector).",
    )
    tags: list[str] = Field(default_factory=list)
    existing_mitre_attack_mapping: list[ExistingMitreMapping] = Field(default_factory=list)

    # --- DetectAI-internal state (not from the vendor) ----------------------------
    status: AlertStatus = AlertStatus.NEW
    dedup_group_id: Optional[str] = None
    incident_id: Optional[str] = None

    model_config = ConfigDict(
        use_enum_values=True,
        json_schema_extra={
            "example": {
                "alert_id": "3f1c9e2a-...",
                "external_alert_id": "elastic-alert-88213",
                "timestamp": "2026-08-26T10:31:19Z",
                "source": "elastic-prod-1",
                "source_product": "elastic_security",
                "severity": "high",
                "rule_name": "PowerShell Encoded Command from Office Process",
                "rule_id": "T1059.001-office-ps",
                "hostname": "WIN10-FINANCE-07",
                "username": "j.doe",
                "process_name": "powershell.exe",
                "parent_process": "winword.exe",
                "command_line": "powershell.exe -enc SQBFAFgA...",
                "destination_ip": "185.203.x.x",
                "destination_port": 443,
                "protocol": "tcp",
                "raw_event": {"...": "original Elastic JSON"},
                "tags": ["office", "powershell", "encoded-command"],
            }
        },
    )

    # --- graceful-missing-data validators -------------------------------------
    @field_validator("source_port", "destination_port")
    @classmethod
    def _validate_port_range(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (0 <= v <= 65535):
            raise ValueError(f"Port {v} out of valid range 0-65535")
        return v

    @field_validator("file_hash")
    @classmethod
    def _normalize_hash_case(cls, v: Optional[str]) -> Optional[str]:
        # Normalize to lowercase so MD5/SHA1/SHA256 compare consistently
        # across sources that report hashes in different casing.
        return v.lower() if v else v

    def has_network_context(self) -> bool:
        return any([self.source_ip, self.destination_ip, self.domain, self.url])

    def has_process_context(self) -> bool:
        return any([self.process_name, self.parent_process, self.command_line])

    def entity_keys(self) -> dict[str, Optional[str]]:
        """Fields usable as correlation/dedup keys. Deliberately excludes
        free-text fields (description, command_line) which are too noisy
        for exact-match correlation.
        """
        return {
            "hostname": self.hostname,
            "username": self.username,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "domain": self.domain,
            "file_hash": self.file_hash,
            "rule_id": self.rule_id,
        }
