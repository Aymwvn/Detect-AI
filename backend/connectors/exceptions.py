"""
Exceptions raised by SIEM connectors.

Per architecture doc section 18: connectors must not fail silently on
unsupported operations. `NotSupportedError` is the specific signal the API
layer uses to tell the frontend "this source doesn't support this action"
rather than surfacing a generic 500.
"""


class ConnectorError(Exception):
    """Base class for all connector-related errors."""


class ConnectorAuthError(ConnectorError):
    """Raised when authenticate() fails — bad credentials, expired token, etc."""


class ConnectorFetchError(ConnectorError):
    """Raised when fetch_alerts()/get_alert() fails for a reason other than auth
    (network error, malformed response, rate limit, source unavailable)."""


class ConnectorNormalizationError(ConnectorError):
    """Raised when a raw vendor payload cannot be normalized into a
    CommonAlertSchema at all — e.g. required fields are missing or malformed.
    This should be rare: normalize_event() should prefer `None` for missing
    optional fields over raising, per CAS's graceful-missing-data design."""


class NotSupportedError(ConnectorError):
    """Raised when a connector is asked to perform an operation its source
    product doesn't support (e.g. acknowledge_alert() on a read-only feed).
    Callers must catch this and surface it as 'not supported by this
    source', never treat it as a generic failure."""

    def __init__(self, operation: str, connector_name: str):
        self.operation = operation
        self.connector_name = connector_name
        super().__init__(f"'{operation}' is not supported by connector '{connector_name}'")
