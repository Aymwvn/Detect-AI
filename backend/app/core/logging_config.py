"""
Structured logging with basic secret redaction.

Per architecture doc section 14 (Security Architecture): secrets must never
be written to logs. This is a first pass — a regex-based safety net, not a
substitute for simply not passing secrets into log calls in the first place.
"""

import logging
import re
import sys

_REDACT_PATTERNS = [
    re.compile(r"(api[_-]?key\s*[=:]\s*)([^\s,&\"']+)", re.IGNORECASE),
    re.compile(r"(authorization:\s*bearer\s+)([^\s,&\"']+)", re.IGNORECASE),
    re.compile(r"(password\s*[=:]\s*)([^\s,&\"']+)", re.IGNORECASE),
    re.compile(r"(secret[_-]?key\s*[=:]\s*)([^\s,&\"']+)", re.IGNORECASE),
]


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for pattern in _REDACT_PATTERNS:
            msg = pattern.sub(r"\1[REDACTED]", msg)
        record.msg = msg
        record.args = ()
        return True


def configure_logging(debug: bool = False) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(RedactingFilter())
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if debug else logging.INFO)
