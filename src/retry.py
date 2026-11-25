#!/usr/bin/env python3
"""One retry for transient LLM provider errors, shared by the explainer and the specialist.

Only server-side and network trouble is retried (HTTP 5xx, timeouts, dropped
connections): a second try a moment later often works. Client errors (400 bad
request, 401 key, 404 model, 429 quota) are not: repeating them only adds delay.
"""
import time

RETRY_DELAY = 2.0   # seconds before the single retry
# Provider SDK exception names for timeouts and network errors (no HTTP status there).
TRANSIENT_NAMES = {"ServerError", "InternalServerError", "OverloadedError",
                   "APITimeoutError", "APIConnectionError", "TimeoutException",
                   "ReadTimeout", "ConnectTimeout", "ConnectError", "RemoteProtocolError"}


def is_transient(exc):
    """True for HTTP 5xx and for timeout / connection errors."""
    for attr in ("code", "status_code"):        # google-genai: code, anthropic: status_code
        status = getattr(exc, attr, None)
        if isinstance(status, int):
            return 500 <= status <= 599
    return type(exc).__name__ in TRANSIENT_NAMES


def call_with_retry(fn, *args, delay=RETRY_DELAY, sleep=time.sleep):
    """Return (result, retried). A failed retry re-raises with exc.oasis_retried = True."""
    try:
        return fn(*args), False
    except Exception as exc:
        if not is_transient(exc):
            raise
    sleep(delay)
    try:
        return fn(*args), True
    except Exception as exc:
        exc.oasis_retried = True
        raise
