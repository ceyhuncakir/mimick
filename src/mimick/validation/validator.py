"""Dynamic finding validation — replays reproduction steps from each finding.

Each finding carries a ``reproduction`` list of HTTP request steps with
expected outcomes.  The validator replays every step with a fresh request
and checks the ``expect`` conditions.

Session cookies are automatically propagated between steps so that
multi-step flows (register -> login -> exploit) work correctly.

Only the **last step** determines CONFIRMED/UNCONFIRMED — earlier steps
are setup (session establishment) and their failures are tolerated.

Statuses:
  CONFIRMED   — last reproduction step passed its expect checks
  UNCONFIRMED — last reproduction step failed
  SKIPPED     — no reproduction steps were provided
  ERROR       — request failed entirely
"""

from __future__ import annotations

import asyncio
from typing import Any

from mimick.logger import get_logger
from mimick.tracker import AttackTracker, GraphNode
from mimick.validation.http import (
    VALIDATION_DELAY,
    check_expect,
    extract_cookies,
    http_request,
    inject_cookies,
)

log = get_logger("validator")


# ── Step replay ───────────────────────────────────────────────────────


def _replay_step(
    step: dict[str, Any],
    session_cookies: dict[str, str],
) -> tuple[bool, str, dict[str, str]]:
    """Replay a single reproduction step.

    Returns ``(passed, detail, updated_cookies)``.
    """
    method = step.get("method", "GET").upper()
    url = step.get("url", "")
    headers = dict(step.get("headers") or {})
    body = step.get("body")
    expect = step.get("expect") or {}

    if not url:
        return False, "no URL in step", session_cookies

    inject_cookies(headers, session_cookies)

    status, resp_hdrs, resp_body = http_request(url, method, headers, body)

    new_cookies = extract_cookies(resp_hdrs)
    merged = {**session_cookies, **new_cookies}

    ok, detail = check_expect(expect, status, resp_hdrs, resp_body)
    return ok, detail, merged


def _validate_one(node: GraphNode) -> tuple[str, str]:
    """Validate one finding by replaying its reproduction steps.

    Only the **last step** determines the verdict.
    """
    steps: list[dict] = node.data.get("reproduction") or []

    if not steps:
        return "SKIPPED", "no reproduction steps provided"

    all_details: list[str] = []
    session_cookies: dict[str, str] = {}
    last_passed = False

    for i, step in enumerate(steps, 1):
        try:
            passed, detail, session_cookies = _replay_step(step, session_cookies)
        except Exception as exc:
            passed, detail = False, f"{type(exc).__name__}: {exc}"

        prefix = f"step {i}" if len(steps) > 1 else ""
        if prefix:
            all_details.append(f"{prefix}: {detail}")
        else:
            all_details.append(detail)

        last_passed = passed

    combined = "; ".join(all_details)
    if last_passed:
        return "CONFIRMED", combined
    return "UNCONFIRMED", combined


# ── Public API ────────────────────────────────────────────────────────


async def validate_findings(tracker: AttackTracker) -> list[dict[str, str]]:
    """Replay reproduction steps for every finding in *tracker*.

    Updates each finding node in-place with ``validation_status`` and
    ``validation_detail``.

    Returns list of result dicts.
    """
    findings = [n for n in tracker._nodes if n.type == "finding"]
    if not findings:
        log.info("No findings to validate")
        return []

    log.info("Validating %d finding(s) …", len(findings))
    results: list[dict[str, str]] = []

    for node in findings:
        steps = node.data.get("reproduction") or []
        log.info(
            "  [%s] %s  (%d step%s) …",
            node.data.get("severity", "?"),
            node.label,
            len(steps),
            "s" if len(steps) != 1 else "",
        )
        status, detail = await asyncio.to_thread(_validate_one, node)

        node.data["validation_status"] = status
        node.data["validation_detail"] = detail
        results.append(
            {
                "id": node.id,
                "title": node.label,
                "severity": node.data.get("severity", ""),
                "url": node.data.get("url", ""),
                "status": status,
                "detail": detail,
            }
        )
        log.info("    → %s  %s", status, detail[:120])
        await asyncio.sleep(VALIDATION_DELAY)

    c = sum(1 for r in results if r["status"] == "CONFIRMED")
    u = sum(1 for r in results if r["status"] == "UNCONFIRMED")
    s = sum(1 for r in results if r["status"] == "SKIPPED")
    e = sum(1 for r in results if r["status"] == "ERROR")
    log.info(
        "Validation: %d confirmed, %d unconfirmed, %d skipped, %d errors", c, u, s, e
    )
    return results
