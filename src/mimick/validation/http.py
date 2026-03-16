"""Shared HTTP helpers for finding validation.

Provides a lightweight HTTP client, cookie extraction/injection, and
expect-condition checking used by both the internal validator and the
generated standalone validation scripts.
"""

from __future__ import annotations

import re
import ssl
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

# ── Constants ─────────────────────────────────────────────────────────

VALIDATION_TIMEOUT = 12
VALIDATION_DELAY = 0.3

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

_COOKIE_SPLIT_RE = re.compile(r",\s*(?=[A-Za-z_][A-Za-z0-9_]*=)")
_PLACEHOLDER_RE = re.compile(r"REPLACE[_A-Z]*", re.IGNORECASE)


# ── HTTP request ──────────────────────────────────────────────────────


def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = VALIDATION_TIMEOUT,
) -> tuple[int, dict[str, str], str]:
    """Fire an HTTP request and return (status, headers_dict, body).

    Handles both 2xx and error responses uniformly.
    """
    data = body.encode() if body else None
    req = Request(url, method=method, data=data)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = urlopen(req, timeout=timeout, context=SSL_CTX)
        resp_body = resp.read().decode(errors="replace")
        resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp_hdrs, resp_body
    except URLError as exc:
        if hasattr(exc, "code"):
            resp_body = (
                exc.read().decode(errors="replace") if hasattr(exc, "read") else ""
            )
            resp_hdrs = (
                {k.lower(): v for k, v in exc.headers.items()}
                if hasattr(exc, "headers")
                else {}
            )
            return exc.code, resp_hdrs, resp_body
        raise


# ── Cookie helpers ────────────────────────────────────────────────────


def extract_cookies(resp_hdrs: dict[str, str]) -> dict[str, str]:
    """Parse Set-Cookie header(s) into a {name: value} dict."""
    cookies: dict[str, str] = {}
    raw = resp_hdrs.get("set-cookie", "")
    if not raw:
        return cookies
    for part in _COOKIE_SPLIT_RE.split(raw):
        nv = part.split(";")[0].strip()
        if "=" in nv:
            name, _, value = nv.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


def build_cookie_header(cookies: dict[str, str]) -> str:
    """Build a ``Cookie`` header value from a cookie jar dict."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def inject_cookies(headers: dict[str, str], session_cookies: dict[str, str]) -> None:
    """Inject session cookies into *headers* in-place.

    * No ``Cookie`` header → add one from *session_cookies*.
    * ``Cookie`` contains ``REPLACE`` placeholders → substitute.
    * ``Cookie`` is a real value → leave untouched.
    """
    if not session_cookies:
        return

    cookie_key = None
    for k in headers:
        if k.lower() == "cookie":
            cookie_key = k
            break

    cookie_val = build_cookie_header(session_cookies)
    if cookie_key is None:
        headers["Cookie"] = cookie_val
    elif _PLACEHOLDER_RE.search(headers[cookie_key]):
        headers[cookie_key] = cookie_val


# ── Expect checking ───────────────────────────────────────────────────


def check_expect(
    expect: dict[str, Any],
    status: int,
    headers: dict[str, str],
    body: str,
) -> tuple[bool, str]:
    """Check a single expect dict against a response.  Returns ``(ok, detail)``."""
    passed: list[str] = []
    failed: list[str] = []

    if "status" in expect:
        want = expect["status"]
        if status == want:
            passed.append(f"status={status}")
        else:
            failed.append(f"expected status {want}, got {status}")

    if "body_contains" in expect:
        needle = expect["body_contains"]
        if needle in body:
            passed.append(f"body contains '{needle[:40]}'")
        else:
            failed.append(f"body missing '{needle[:40]}'")

    if "body_not_contains" in expect:
        needle = expect["body_not_contains"]
        if needle not in body:
            passed.append(f"body does not contain '{needle[:40]}'")
        else:
            failed.append(f"body unexpectedly contains '{needle[:40]}'")

    if "header_absent" in expect:
        hdr = expect["header_absent"].lower()
        if hdr not in headers:
            passed.append(f"header '{hdr}' absent")
        else:
            failed.append(f"header '{hdr}' present (expected absent)")

    if "header_present" in expect:
        hdr = expect["header_present"].lower()
        if hdr in headers:
            passed.append(f"header '{hdr}' present")
        else:
            failed.append(f"header '{hdr}' absent (expected present)")

    if "header_contains" in expect:
        for hdr_name, want_sub in expect["header_contains"].items():
            actual = headers.get(hdr_name.lower(), "")
            if want_sub.lower() in actual.lower():
                passed.append(f"{hdr_name} contains '{want_sub}'")
            else:
                failed.append(f"{hdr_name}='{actual[:50]}' missing '{want_sub}'")

    if "status_not" in expect:
        unwanted = expect["status_not"]
        if status != unwanted:
            passed.append(f"status {status} (not {unwanted})")
        else:
            failed.append(f"status is {unwanted} (unwanted)")

    if "min_body_length" in expect:
        want_len = expect["min_body_length"]
        if len(body) >= want_len:
            passed.append(f"body {len(body)}B >= {want_len}")
        else:
            failed.append(f"body {len(body)}B < {want_len}")

    if failed:
        return False, "; ".join(failed)
    if passed:
        return True, "; ".join(passed)
    return True, "request succeeded (no assertions)"
