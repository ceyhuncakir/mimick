from __future__ import annotations

from typing import Any

from mimick.agent.deps import MimickDeps, UNPRODUCTIVE_THRESHOLD
from mimick.planner.models import Phase


def build_dynamic_context(deps: MimickDeps) -> str:
    """Assemble live assessment context from tracker and planner state.

    Args:
        deps: The current agent dependencies.

    Returns:
        Markdown-formatted context string, or empty string if nothing
        to inject.
    """
    sections: list[str] = []

    if deps.planner:
        deps.planner.perceive(deps.tracker, deps.iteration)
        directive: str = deps.planner.build_directive(deps.iteration)
        if directive:
            sections.append(directive)

    if deps.iteration < 2:
        return "\n\n".join(sections)

    sections.append("# Live Assessment Context (auto-updated each iteration)")

    tech: dict[str, list[str]] = deps.tracker.get_tech_summary()
    if tech:
        lines: list[str] = ["## Detected Tech Stack"] + [
            f"- **{host}**: {', '.join(techs)}"
            for host, techs in list(tech.items())[:10]
        ]
        sections.append("\n".join(lines))

    wafs: list[str] = deps.tracker.get_waf_info()
    if wafs:
        sections.append(
            f"## WAF Detected\n- {', '.join(wafs)}\nAdjust payloads accordingly."
        )

    failures: dict[str, int] = deps.get_failure_summary()
    if failures:
        failure_advice: dict[str, str] = {
            "sqli": "Try higher sqlmap level/risk, tamper scripts, or different injection points.",
            "xss": "Try different encoding, event handlers, or DOM-based vectors.",
            "vuln_scan": "Focus on manual testing instead of template scans.",
            "fuzzing": "Try different wordlists or switch to manual endpoint discovery.",
            "param_discovery": "Use browser JS analysis or manual parameter guessing.",
            "oob": "Check if outbound connections are blocked; try DNS-only exfil.",
        }
        lines = ["## Attack Failures (adapt your strategy)"] + [
            f"- **{atype}** failed {count} time(s). {failure_advice.get(atype, 'Try a different approach.')}"
            for atype, count in failures.items()
        ]
        sections.append("\n".join(lines))

    if deps._shared_child_findings:
        lines = ["## Child Agent Findings (do NOT duplicate)"] + [
            f"- [{f.get('severity', '?').upper()}] {f.get('title', '?')} at {f.get('url', '?')}"
            for f in deps._shared_child_findings[:20]
        ]
        sections.append("\n".join(lines))

    params: dict[str, list[str]] = deps.tracker.get_discovered_params()
    if params:
        lines = ["## Discovered Parameters (test each for injection)"] + [
            f"- **{url}**: {', '.join(plist[:8])}"
            for url, plist in list(params.items())[:10]
        ]
        sections.append("\n".join(lines))

    endpoints: list[str] = deps.tracker.get_discovered_endpoints()
    findings: list[dict[str, Any]] = deps.tracker.get_findings_summary()

    finding_urls: set[str] = {f.get("url", "").rstrip("/").lower() for f in findings}
    strategy_urls: set[str] = {
        url.lower().rstrip("/") for url in deps._strategies_tried
    }
    tested_set: set[str] = finding_urls | strategy_urls

    untested_endpoints: list[str] = (
        [ep for ep in endpoints if ep.lower().rstrip("/") not in tested_set]
        if endpoints
        else []
    )

    if endpoints:
        lines = [f"## Coverage: {len(endpoints)} discovered, {len(findings)} findings"]
        if untested_endpoints:
            lines += [
                "",
                f"**{len(untested_endpoints)} endpoint(s) discovered but NOT yet tested:**",
            ]
            lines += [f"- `{ep}`" for ep in untested_endpoints[:10]]
            if len(untested_endpoints) > 10:
                lines.append(f"- ... and {len(untested_endpoints) - 10} more")
            lines += [
                "",
                "Create tasks for untested endpoints with `create_task()` or test them directly.",
            ]
        sections.append("\n".join(lines))

    stuck: dict[str, list[str]] = deps.get_stuck_targets(min_attempts=3)
    if stuck:
        lines = [
            "## Stuck Targets — Change Your Approach",
            "",
            "You have made 3+ attempts on these targets without a finding. "
            "**Pick a fundamentally different approach.**",
            "",
        ]
        for url, strategies in list(stuck.items())[:3]:
            unique: list[str] = sorted(set(strategies))
            lines += [f"### `{url}`", "**Already tried:**"]
            lines += [f"  - {s}" for s in unique]
            lines.append("")
        sections.append("\n".join(lines))

    if deps.planner and deps.iteration >= 5:
        _maybe_inject_vuln_hint(deps, sections)

    blockers: list[str] = []

    if deps.planner:
        high_pri = [
            n
            for n in deps.planner.tree._nodes.values()
            if n.status.value == "pending" and n.phase.value >= 4 and n.priority >= 70
        ]
        for n in sorted(high_pri, key=lambda x: -x.priority)[:5]:
            blockers.append(
                f"[TASK] [{n.category}] (priority={n.priority}) {n.description[:80]}"
            )

    for ep in untested_endpoints[:5]:
        blockers.append(f"[UNTESTED] `{ep}`")

    if blockers:
        lines = [
            "## ⚠ DO NOT WRITE THE FINAL REPORT YET",
            "",
            f"You have **{len(blockers)} untested surfaces** that need attention:",
        ]
        lines += [f"- {b}" for b in blockers[:8]]
        if len(blockers) > 8:
            lines.append(f"- ... and {len(blockers) - 8} more")
        lines += [
            "",
            "Create tasks with `create_task()` for untested endpoints, "
            "or test them directly. Only write the report when all surfaces are covered.",
        ]
        sections.append("\n".join(lines))

    if deps._unproductive_streak >= UNPRODUCTIVE_THRESHOLD:
        sections.append(
            "## ⚠ Stale Assessment\n"
            f"The last {deps._unproductive_streak} iterations discovered nothing new. "
            "**STOP and reflect.** Pick an untested attack vector or write the final report."
        )

    return "\n\n".join(sections) if sections else ""


def _maybe_inject_vuln_hint(deps: MimickDeps, sections: list[str]) -> None:
    """Inject a vulnerability lookup hint when the agent is stuck on a task.

    Args:
        deps: The current agent dependencies.
        sections: Mutable list of context sections to append to.
    """
    if not deps.planner:
        return
    active = deps.planner.tree.get_active_task()
    if not active or active.phase not in (
        Phase.VULN_HUNT,
        Phase.EXPLOIT,
        Phase.ESCALATE,
    ):
        return

    iters_on_task: int = deps.iteration - deps.planner.tree._active_since_iteration
    if iters_on_task < 3:
        return

    category_query_map: dict[str, tuple[str, str | None]] = {
        "sqli": ("sqli", None),
        "xss": ("xss", None),
        "ssti": ("ssti", None),
        "cmd_injection": ("command injection", None),
        "ssrf": ("ssrf", None),
        "idor": ("idor", None),
        "path_traversal": ("lfi", "Wrappers"),
        "file_upload": ("upload", None),
        "auth_bypass": ("authentication", None),
        "rce": ("ssti", None),
        "sqli_extract": ("sqli", None),
        "lfi_escalate": ("lfi", "Wrappers"),
    }

    lookup = category_query_map.get(active.category)
    if not lookup:
        return

    inject_key: str = f"{active.category}:{active.target_url}"
    if inject_key in deps._auto_injected_lookups:
        return
    deps._auto_injected_lookups.add(inject_key)

    query, subtopic = lookup

    tech_hint: str = ""
    for _host, techs in deps.tracker.get_tech_summary().items():
        tech_lower: str = " ".join(techs).lower()
        for keyword, label in [
            ("php", "PHP"),
            ("python", "Python"),
            ("flask", "Python"),
            ("django", "Python"),
            ("node", "Node"),
            ("express", "Node"),
            ("java", "Java"),
            ("spring", "Java"),
        ]:
            if keyword in tech_lower:
                tech_hint = label
                break
        if tech_hint:
            break

    st_arg: str | None = subtopic or tech_hint
    lookup_call: str = f'vuln_lookup(query="{query}"'
    if st_arg:
        lookup_call += f', subtopic="{st_arg}"'
    lookup_call += ")"

    sections.append(
        f"## Hint: Stuck on `{active.category}` for {iters_on_task} iterations\n\n"
        f"**Call `{lookup_call}` NOW** for engine-specific payloads and bypass techniques."
    )
