"""
SIEMConnector — the interface every SIEM/EDR/cloud security connector
implements (architecture doc section 18).

Design rules:
- Every connector converts vendor-specific data into CommonAlertSchema.
  Nothing outside this module (dedup, correlation, risk scoring, AI
  analysis, the API layer) is ever allowed to touch a vendor-specific
  field directly — that's the whole point of the CAS boundary.
- Not every vendor supports every operation (e.g. some feeds are read-only
  and can't acknowledge alerts). Unsupported operations raise
  NotSupportedError explicitly rather than failing silently or faking success.
- Connectors never write to the database directly. They hand normalized
  CommonAlertSchema objects back to the ingestion service (Phase 10), which
  keeps normalization logic independently testable — a connector's
  correctness can be verified with zero DB, zero network.
- Treat all fetched data as untrusted (architecture doc section 14): a
  connector should never `eval`, deserialize with pickle, or otherwise
  execute anything from a raw payload. Parsing should be strictly
  data-in/data-out.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from app.schemas import CommonAlertSchema
from connectors.exceptions import NotSupportedError

# A RawAlert is whatever shape the vendor gives us — deliberately untyped
# beyond "a JSON-like dict" since every source's payload differs. It only
# gains structure once normalize_event() turns it into a CommonAlertSchema.
RawAlert = dict[str, Any]


class SIEMConnector(ABC):
    """Base class for all SIEM/EDR/cloud connectors.

    Subclasses MUST implement: authenticate, fetch_alerts, normalize_event.
    Subclasses MAY override: get_alert, acknowledge_alert — the defaults
    here raise NotSupportedError, which is the correct behavior for any
    connector whose source doesn't support single-alert lookups or
    acknowledgment (rather than every connector re-implementing that
    boilerplate).
    """

    #: Must match a value in app.schemas.SourceProduct. Subclasses set this.
    source_product: str = "other"

    def __init__(self, connector_id: str, name: str, config: dict[str, Any] | None = None):
        self.connector_id = connector_id
        self.name = name
        self.config = config or {}

    # --- required interface --------------------------------------------------

    @abstractmethod
    def authenticate(self) -> bool:
        """Verify/establish credentials with the source. Returns True on
        success. Should raise ConnectorAuthError (not return False) when
        credentials are present but invalid, so callers can distinguish
        "not configured yet" from "misconfigured"."""
        raise NotImplementedError

    @abstractmethod
    def fetch_alerts(self, since: datetime) -> list[RawAlert]:
        """Fetch raw alerts created/updated since the given timestamp.
        Returns the vendor's native format, unmodified — normalization
        happens separately in normalize_event() so the two concerns
        (fetching vs. parsing) can be tested and fail independently."""
        raise NotImplementedError

    @abstractmethod
    def normalize_event(self, raw: RawAlert) -> CommonAlertSchema:
        """Convert one raw vendor alert into a CommonAlertSchema.

        Must gracefully handle missing fields (leave them None, never
        guess or fabricate — see CommonAlertSchema's own design rules).
        `raw_event` on the returned schema must contain the untouched
        original payload so analysts can always inspect source truth.
        """
        raise NotImplementedError

    # --- optional interface, safe defaults ------------------------------------

    def get_alert(self, alert_id: str) -> RawAlert:
        """Fetch a single alert by its vendor-native ID. Not every source
        supports single-alert lookup (some are batch/poll-only feeds)."""
        raise NotSupportedError("get_alert", self.name)

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged/seen on the source system itself.
        Many read-only feeds (webhook, syslog) can't support this."""
        raise NotSupportedError("acknowledge_alert", self.name)

    # --- shared helpers available to all subclasses ---------------------------

    @staticmethod
    def safe_get(raw: RawAlert, *path: str, default: Any = None) -> Any:
        """Safely walk a nested dict path without raising KeyError, e.g.
        safe_get(raw, "process", "parent", "name"). Vendor payloads vary
        wildly in nesting; connectors should use this instead of raw[...][...]
        chains that blow up the moment one source omits a field."""
        current: Any = raw
        for key in path:
            if not isinstance(current, dict) or key not in current:
                return default
            current = current[key]
        return current if current is not None else default

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.connector_id!r} name={self.name!r}>"
