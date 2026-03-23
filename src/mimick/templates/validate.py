from __future__ import annotations

import json
import re
import ssl
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

TIMEOUT = 12

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http(url, method="GET", headers=None, body=None):
    data = body.encode() if body else None
    req = Request(url, method=method, data=data)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    opener = build_opener(HTTPSHandler(context=_CTX), _NoRedirect)
    try:
        resp = opener.open(req, timeout=TIMEOUT)
        rbody = resp.read().decode(errors="replace")
        rhdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, rhdrs, rbody
    except HTTPError as e:
        rbody = e.read().decode(errors="replace") if e.fp else ""
        rhdrs = {k.lower(): v for k, v in e.headers.items()}
        return e.code, rhdrs, rbody
    except URLError as e:
        if hasattr(e, "code"):
            rbody = e.read().decode(errors="replace") if hasattr(e, "read") else ""
            rhdrs = (
                {k.lower(): v for k, v in e.headers.items()}
                if hasattr(e, "headers")
                else {}
            )
            return e.code, rhdrs, rbody
        raise


def extract_cookies(resp_hdrs):
    raw = resp_hdrs.get("set-cookie", "")
    if not raw:
        return {}
    parts = re.split(r",\s*(?=[A-Za-z_][A-Za-z0-9_]*=)", raw)
    return {
        nv.split("=", 1)[0].strip(): nv.split("=", 1)[1].strip()
        for part in parts
        for nv in [part.split(";")[0].strip()]
        if "=" in nv
    }


_PLACEHOLDER_RE = re.compile(r"REPLACE[_A-Z]*", re.IGNORECASE)


def inject_cookies(headers, session_cookies):
    if not session_cookies:
        return
    cookie_val = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
    cookie_key = next((k for k in headers if k.lower() == "cookie"), None)
    if cookie_key is None:
        headers["Cookie"] = cookie_val
    elif _PLACEHOLDER_RE.search(headers[cookie_key]):
        headers[cookie_key] = cookie_val


def check_expect(expect, status, headers, body):
    passed, failed = [], []
    checks = [
        (
            "status",
            lambda: status == expect["status"],
            lambda: f"status {status} (want {expect['status']})",
        ),
        (
            "body_contains",
            lambda: expect["body_contains"] in body,
            lambda: f"body {'contains' if expect['body_contains'] in body else 'missing'} '{expect['body_contains'][:40]}'",
        ),
        (
            "body_not_contains",
            lambda: expect["body_not_contains"] not in body,
            lambda: f"body '{expect['body_not_contains'][:40]}' {'absent' if expect['body_not_contains'] not in body else 'present'}'",
        ),
        (
            "header_absent",
            lambda: expect["header_absent"].lower() not in headers,
            lambda: f"header '{expect['header_absent']}' {'absent' if expect['header_absent'].lower() not in headers else 'present'}'",
        ),
        (
            "header_present",
            lambda: expect["header_present"].lower() in headers,
            lambda: f"header '{expect['header_present']}' {'present' if expect['header_present'].lower() in headers else 'absent'}'",
        ),
        (
            "status_not",
            lambda: status != expect["status_not"],
            lambda: f"status {status} (not {expect['status_not']})",
        ),
        (
            "min_body_length",
            lambda: len(body) >= expect["min_body_length"],
            lambda: f"body {len(body)}B (min {expect['min_body_length']})",
        ),
    ]
    for key, test_fn, msg_fn in checks:
        if key in expect:
            (passed if test_fn() else failed).append(msg_fn())
    if "header_contains" in expect:
        for hname, want in expect["header_contains"].items():
            actual = headers.get(hname.lower(), "")
            ok = want.lower() in actual.lower()
            (passed if ok else failed).append(
                f"{hname}={'ok' if ok else repr(actual[:40])}"
            )
    return (
        (False, "; ".join(failed))
        if failed
        else (True, "; ".join(passed) if passed else "ok")
    )


def validate(finding):
    steps = finding.get("reproduction") or []
    if not steps:
        return "SKIPPED", "no reproduction steps"
    details, last_passed, session_cookies = [], False, {}
    for i, step in enumerate(steps, 1):
        try:
            hdrs = dict(step.get("headers") or {})
            inject_cookies(hdrs, session_cookies)
            s, h, b = http(
                step.get("url", ""),
                step.get("method", "GET"),
                hdrs,
                step.get("body"),
            )
            session_cookies.update(extract_cookies(h))
            p, d = check_expect(step.get("expect", {}), s, h, b)
        except Exception as e:
            p, d = False, str(e)
        prefix = f"step {i}: " if len(steps) > 1 else ""
        details.append(f"{prefix}{d}")
        last_passed = p
    return ("CONFIRMED" if last_passed else "UNCONFIRMED"), "; ".join(details)


def load_findings(path):
    with open(path) as f:
        return json.load(f)


def main():
    global TIMEOUT

    findings_path = None
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--timeout" and i + 1 < len(args):
            TIMEOUT = int(args[i + 1])
            i += 2
        elif args[i] == "--findings" and i + 1 < len(args):
            findings_path = args[i + 1]
            i += 2
        else:
            findings_path = args[i]
            i += 1

    if not findings_path:
        candidates = sorted(Path(".").glob("*_findings.json"), reverse=True)
        if not candidates:
            print(
                f"{RED}No findings file found. Pass --findings path/to/findings.json{RESET}"
            )
            sys.exit(2)
        findings_path = str(candidates[0])

    findings = load_findings(findings_path)

    print(f"\n{BOLD}Mimick Finding Validator{RESET}")
    print(f"Findings: {len(findings)} (from {findings_path})\n")
    print("-" * 72)

    confirmed = 0
    for i, f in enumerate(findings, 1):
        try:
            status, detail = validate(f)
        except Exception as e:
            status, detail = "ERROR", str(e)

        if status == "CONFIRMED":
            icon, color = "\u2705", GREEN
            confirmed += 1
        elif status == "SKIPPED":
            icon, color = "\u23ed\ufe0f ", YELLOW
        elif status == "UNCONFIRMED":
            icon, color = "\u26a0\ufe0f ", YELLOW
        else:
            icon, color = "\u274c", RED

        sev = f["severity"].upper()
        print(f"  {color}{icon} [{sev:>8}] {f['title'][:55]}{RESET}")
        print(f"           {status}: {detail[:80]}")
        time.sleep(0.3)

    print("-" * 72)
    total = len(findings)
    skipped = sum(1 for f in findings if not f.get("reproduction"))
    testable = total - skipped
    print(f"\n{BOLD}{confirmed}/{testable} testable findings confirmed")
    if skipped:
        print(f"{skipped} finding(s) skipped (no reproduction steps){RESET}")
    if confirmed < testable:
        print(
            f"{YELLOW}{testable - confirmed} finding(s) could not be auto-confirmed.{RESET}"
        )
    print()
    sys.exit(0 if confirmed == testable else 1)


if __name__ == "__main__":
    main()
