"""Logging with secret redaction.

Any code path that ever touches a raw provider credential registers it here.
The redaction filter scrubs registered values out of every log line, so even
a buggy or overly chatty log statement cannot leak a live token. This is
defense in depth — the primary rule is still "never log credentials".
"""

import logging
import threading

_SECRET_REGISTRY: set[str] = set()
_LOCK = threading.Lock()
_MIN_SECRET_LEN = 8  # don't register trivially short strings; they would over-redact

REDACTED = "[REDACTED]"


def register_secret(value: str | bytes | None) -> None:
    """Register a sensitive value so it can never appear in a log line."""
    if not value:
        return
    if isinstance(value, bytes):
        try:
            value = value.decode()
        except UnicodeDecodeError:
            return
    if len(value) < _MIN_SECRET_LEN:
        return
    with _LOCK:
        _SECRET_REGISTRY.add(value)


def scrub(text: str) -> str:
    """Replace every registered secret occurring in ``text`` with a marker."""
    with _LOCK:
        secrets = list(_SECRET_REGISTRY)
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, REDACTED)
    return text


def clear_registry() -> None:
    """Testing hook: forget all registered secrets."""
    with _LOCK:
        _SECRET_REGISTRY.clear()


class SecretRedactionFilter(logging.Filter):
    """Attached to handlers; rewrites any record whose message contains a secret."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        scrubbed = scrub(message)
        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
        # Tracebacks are formatted at handler level, after this filter runs,
        # so a secret inside an exception message would bypass the message
        # scrub above. Pre-format and scrub the traceback into exc_text:
        # Formatter.format computes exc_text only when it is empty, so every
        # handler downstream reuses the scrubbed text and never re-formats
        # the raw exc_info.
        if record.exc_info and not record.exc_text:
            try:
                record.exc_text = scrub(logging.Formatter().formatException(record.exc_info))
            except Exception:
                # Unformattable means unscannable; drop the traceback rather
                # than let a handler format the raw exc_info later.
                record.exc_info = None
        elif record.exc_text:
            record.exc_text = scrub(record.exc_text)
        if record.stack_info:
            record.stack_info = scrub(record.stack_info)
        return True


def configure_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        root.addHandler(handler)
    redaction = SecretRedactionFilter()
    for handler in root.handlers:
        if not any(isinstance(f, SecretRedactionFilter) for f in handler.filters):
            handler.addFilter(redaction)
