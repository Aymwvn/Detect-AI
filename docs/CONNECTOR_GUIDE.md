# Adding a New Connector

DetectAI's connector architecture (architecture doc §18) is built around
one abstract interface — `SIEMConnector` (`backend/connectors/base.py`) —
implemented four times already (`elastic.py`, `splunk.py`, `wazuh.py`,
`generic.py`). This is the pattern all four follow; a new connector should
look the same shape.

## The interface

```python
class SIEMConnector(ABC):
    @abstractmethod
    def authenticate(self) -> bool: ...

    @abstractmethod
    def fetch_alerts(self, since: datetime) -> list[RawAlert]: ...

    @abstractmethod
    def normalize_event(self, raw: RawAlert) -> CommonAlertSchema: ...

    # Optional — default raises NotSupportedError:
    def get_alert(self, alert_id: str) -> RawAlert: ...
    def acknowledge_alert(self, alert_id: str) -> bool: ...
```

`RawAlert` is just `dict[str, Any]` — whatever shape the vendor gives you.
It only gains structure once `normalize_event()` turns it into a
`CommonAlertSchema`.

## Steps

1. **Add the source to `SourceProduct`** (`app/schemas/common_alert_schema.py`)
   if it's a genuinely new product — the four built-in connectors already
   cover `elastic_security`, `splunk`, `wazuh`, `generic_webhook`, `generic_rest`.

2. **Create `backend/connectors/your_siem.py`**, subclassing `SIEMConnector`.

   - `authenticate()`: verify credentials/connectivity. Raise
     `ConnectorAuthError` (don't just return `False`) so callers can tell
     "not configured" apart from "misconfigured."
   - `fetch_alerts(since)`: return the vendor's raw alerts unmodified —
     don't normalize here, that's a separate step so fetching and parsing
     can fail (and be tested) independently.
   - `normalize_event(raw)`: map every field you can into
     `CommonAlertSchema`. Missing fields become `None` — never guess or
     fabricate a value (this is the single most important rule; see
     `CommonAlertSchema`'s own docstring).
   - `get_alert()` / `acknowledge_alert()`: only override if the source
     actually supports single-lookup / acknowledgment. Otherwise leave
     the base class defaults, which correctly raise `NotSupportedError`.

3. **Use `self.safe_get(raw, "a", "b", "c")`** instead of `raw["a"]["b"]["c"]`
   chains — vendor payloads vary in nesting and a missing key shouldn't
   raise `KeyError` mid-normalization. See `connectors/elastic.py`'s
   `_dotted_get` helper for the pattern with deeply nested JSON.

4. **Lazy-import the vendor's client library** (if any) inside a
   `_build_client()` method, and accept `client=` in `__init__` for test
   injection. This is why none of the four existing connectors require
   their optional dependency (`elasticsearch-py`, etc.) unless that
   specific connector is actually instantiated — see `connectors/elastic.py`.

5. **Write tests** (`backend/tests/test_your_siem_connector.py`) using a
   fake client shaped like the real one (`.get()`/`.post()` returning fake
   response objects). No live SIEM instance is needed or expected — every
   existing connector's tests work this way, since a real cluster/instance
   isn't available in CI either. Cover at minimum:
   - `authenticate()` success and failure
   - `fetch_alerts()` → `normalize_event()` full round trip on a realistic
     sample payload
   - missing/optional fields don't raise
   - any `NotSupportedError` paths you didn't override

6. **If the vendor requires an extra Python package**, add it to its own
   `connectors/requirements-your_siem.txt` (see
   `connectors/requirements-elastic.txt`) rather than the core
   `requirements.txt`, so a deployment that doesn't use this connector
   doesn't need to install it.

## What normalize_event() must never do

- Never `eval()`, `pickle.loads()`, or otherwise execute anything from the
  raw payload — treat it as pure data (architecture doc §14: all connector
  input is untrusted).
- Never invent a value for a field the source didn't provide.
- Always preserve the untouched original payload in `raw_event` — analysts
  need to inspect source truth even after normalization.
