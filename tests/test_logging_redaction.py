"""Focused tests for the secret-redaction logging layer.

test_security_properties.py pins the end-to-end invariant; these tests pin
the redaction machinery itself, including the paths the message scrub alone
cannot cover: tracebacks (formatted at handler level, after the filter) and
stack info.
"""

import io
import logging
import sys

import pytest

from credbroker.logging_config import (
    REDACTED,
    SecretRedactionFilter,
    clear_registry,
    register_secret,
    scrub,
)

SECRET = "sk-live-very-secret-provider-token-0011223344"


@pytest.fixture(autouse=True)
def _clean_secret_registry():
    clear_registry()
    yield
    clear_registry()


@pytest.fixture
def log_capture():
    """Attach a real handler + SecretRedactionFilter capturing every log line."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    handler.addFilter(SecretRedactionFilter())
    root = logging.getLogger()
    previous_level = root.level
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)
    yield stream
    root.removeHandler(handler)
    root.setLevel(previous_level)


def test_registered_secret_scrubbed_from_plain_message(log_capture):
    register_secret(SECRET)

    logging.getLogger("redaction.test").info("access token is %s", SECRET)

    logs = log_capture.getvalue()
    assert SECRET not in logs
    assert REDACTED in logs


def test_secret_in_exception_traceback_scrubbed(log_capture):
    register_secret(SECRET)
    logger = logging.getLogger("redaction.test.exc")

    try:
        raise ValueError(f"provider rejected token {SECRET}")
    except ValueError:
        logger.exception("provider call failed")

    logs = log_capture.getvalue()
    assert SECRET not in logs
    assert REDACTED in logs
    # The traceback itself was emitted, not dropped along with the secret.
    assert "Traceback (most recent call last)" in logs
    assert "ValueError" in logs


def test_pre_cached_exc_text_scrubbed(log_capture):
    """A traceback already formatted by an unfiltered handler is still scrubbed."""
    register_secret(SECRET)
    logger = logging.getLogger("redaction.test.cached")

    try:
        raise RuntimeError(f"provider rejected token {SECRET}")
    except RuntimeError:
        exc_info = sys.exc_info()
    record = logger.makeRecord(
        logger.name, logging.ERROR, __file__, 0, "provider call failed", (), exc_info
    )
    record.exc_text = logging.Formatter().formatException(exc_info)
    logger.handle(record)

    logs = log_capture.getvalue()
    assert SECRET not in logs
    assert REDACTED in logs


def test_secret_in_stack_info_scrubbed(log_capture):
    register_secret(SECRET)
    logger = logging.getLogger("redaction.test.stack")

    # stack_info is captured as pre-formatted text by the logging call, so
    # simulate a capture whose source line carried the secret.
    record = logger.makeRecord(
        logger.name,
        logging.INFO,
        __file__,
        0,
        "checkpoint",
        (),
        None,
        sinfo=f'Stack (most recent call last):\n  File "app.py", line 1\n    use("{SECRET}")',
    )
    logger.handle(record)

    logs = log_capture.getvalue()
    assert SECRET not in logs
    assert REDACTED in logs
    assert "Stack (most recent call last)" in logs


def test_short_values_are_not_registered():
    register_secret("short")

    assert scrub("this short value stays") == "this short value stays"


def test_clear_registry_forgets_secrets():
    register_secret(SECRET)
    assert scrub(f"token {SECRET}") == f"token {REDACTED}"

    clear_registry()

    assert scrub(f"token {SECRET}") == f"token {SECRET}"
