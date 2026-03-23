from __future__ import annotations

import re
from urllib.parse import urlparse

from mimick.memory.models import ChainStep, Experience
from mimick.tracker import AttackTracker


def _detect_target_type(tracker: AttackTracker) -> str:
    """Infer target type from discovered assets."""
    endpoints = tracker.get_discovered_endpoints()
    tech = tracker.get_tech_summary()

    all_tech = " ".join(" ".join(v) for v in tech.values()).lower()

    if any(kw in all_tech for kw in ("react", "vue", "angular", "next")):
        return "spa"
    if any("/api/" in ep.lower() for ep in endpoints):
        return "web_api"
    return "web_app"


def _extract_tech_stack(tracker: AttackTracker) -> list[str]:
    """Extract a flat list of technologies from the tracker."""
    tech_map = tracker.get_tech_summary()
    seen: set[str] = set()
    result: list[str] = []
    for techs in tech_map.values():
        for t in techs:
            clean = t.replace("Server: ", "").strip().lower()
            if clean and clean not in seen:
                seen.add(clean)
                result.append(clean)
    return result[:10]


def _build_observation(
    tracker: AttackTracker,
    finding_title: str,
    finding_url: str,
    finding_iteration: int,
) -> str:
    """Build the observation signature from tracker state at finding time.

    Captures what the agent saw leading up to the finding:
    tech stack, endpoints, WAF, and relevant tool outputs.
    """
    parts: list[str] = []

    tech = tracker.get_tech_summary()
    if tech:
        tech_lines = [f"{host}: {', '.join(ts)}" for host, ts in list(tech.items())[:5]]
        parts.append(f"Tech stack: {'; '.join(tech_lines)}")

    wafs = tracker.get_waf_info()
    if wafs:
        parts.append(f"WAF: {', '.join(wafs)}")

    endpoints = tracker.get_discovered_endpoints()
    if endpoints:
        relevant = [ep for ep in endpoints if _url_overlap(ep, finding_url)]
        if not relevant:
            relevant = endpoints[:5]
        parts.append(f"Endpoints: {', '.join(relevant[:5])}")

    params = tracker.get_discovered_params()
    if params:
        param_strs = [
            f"{url}: {', '.join(ps[:5])}" for url, ps in list(params.items())[:3]
        ]
        parts.append(f"Params: {'; '.join(param_strs)}")

    reasoning_context = _extract_reasoning_before(tracker, finding_iteration)
    if reasoning_context:
        parts.append(f"Agent observations: {reasoning_context}")

    return "\n".join(parts) if parts else f"Finding at {finding_url}"


def _url_overlap(ep: str, finding_url: str) -> bool:
    """Check if two URLs share a path prefix."""
    try:
        ep_path = urlparse(ep).path.rstrip("/")
        finding_path = urlparse(finding_url).path.rstrip("/")
        if not ep_path or not finding_path:
            return False
        ep_parts = ep_path.split("/")
        find_parts = finding_path.split("/")
        common = sum(1 for a, b in zip(ep_parts, find_parts) if a == b)
        return common >= 2
    except Exception:
        return False


def _extract_reasoning_before(
    tracker: AttackTracker, finding_iteration: int, max_chars: int = 300
) -> str:
    """Extract key reasoning snippets from events before the finding."""
    reasoning_parts: list[str] = []
    for event in tracker._events:
        if event.get("iteration", 0) > finding_iteration:
            break
        if event.get("type") == "reasoning":
            text = event.get("text", "")
            first_line = text.split("\n")[0].strip()
            if first_line and len(first_line) > 20:
                reasoning_parts.append(first_line[:100])

    recent = reasoning_parts[-3:]
    result = " | ".join(recent)
    return result[:max_chars]


def _build_chain(
    tracker: AttackTracker,
    finding_iteration: int,
) -> list[ChainStep]:
    """Extract the tool-call chain leading to a finding.

    Only includes events AFTER the previous finding to avoid
    contaminating the chain with a different exploit's steps.
    """
    # Find the iteration of the most recent prior finding
    prev_finding_iter = 0
    for event in tracker._events:
        if (
            event.get("type") == "finding"
            and event.get("iteration", 0) < finding_iteration
        ):
            prev_finding_iter = event["iteration"]

    tool_events = [
        e
        for e in tracker._events
        if e.get("type") == "tool_call"
        and prev_finding_iter < e.get("iteration", 0) <= finding_iteration
    ]

    # Cap at 15 most recent steps within this finding's window
    relevant = tool_events[-15:]

    chain: list[ChainStep] = []
    for event in relevant:
        tool = event.get("tool", "")
        args = event.get("args", {})

        if isinstance(args, dict):
            arg_parts = [f"{k}={v}" for k, v in args.items() if v]
            args_str = ", ".join(arg_parts)
        else:
            args_str = str(args)

        stdout = event.get("stdout", "")
        result_summary = _summarize_output(tool, stdout)

        chain.append(
            ChainStep(
                tool=tool,
                args=args_str[:200],
                result_summary=result_summary,
            )
        )

    return chain


def _summarize_output(tool: str, stdout: str, max_len: int = 150) -> str:
    """Create a compact summary of a tool's output."""
    if not stdout:
        return "(no output)"

    lines = stdout.strip().splitlines()
    line_count = len(lines)

    if tool in ("httpx", "nuclei", "ffuf", "dalfox"):
        return f"{line_count} results"
    if tool == "subfinder":
        return f"{line_count} subdomains"
    if tool == "nmap":
        ports = re.findall(r"(\d+/\w+)\s+open", stdout)
        if ports:
            return f"Open ports: {', '.join(ports[:5])}"

    first = lines[0].strip()[:max_len]
    if line_count > 1:
        return f"{first} (+{line_count - 1} lines)"
    return first


def _build_strategy(
    title: str,
    description: str,
    chain: list[ChainStep],
) -> str:
    """Build a concise strategy string from the finding and chain."""
    tool_flow = " → ".join(step.tool for step in chain[-6:])

    parts = [f"{title}."]
    if description:
        first_sentence = description.split(".")[0].strip()
        if first_sentence and len(first_sentence) > 10:
            parts.append(f"{first_sentence}.")
    if tool_flow:
        parts.append(f"Chain: {tool_flow}.")

    return " ".join(parts)[:500]


def extract_experience(
    tracker: AttackTracker,
    finding_title: str,
    finding_severity: str,
    finding_url: str,
    finding_description: str,
    finding_iteration: int,
    vuln_type: str = "",
) -> Experience:
    """Extract a full Experience from the tracker after a finding is confirmed.

    The vuln_type is provided by the agent — it knows what class of
    vulnerability it found. This allows the experience DB to grow
    organically with any vulnerability type, not just pre-defined ones.
    """
    tech_stack = _extract_tech_stack(tracker)
    target_type = _detect_target_type(tracker)
    observation = _build_observation(
        tracker, finding_title, finding_url, finding_iteration
    )
    chain = _build_chain(tracker, finding_iteration)

    strategy = _build_strategy(finding_title, finding_description, chain)

    return Experience(
        strategy=strategy,
        observation=observation,
        finding_title=finding_title,
        vuln_type=vuln_type or "uncategorized",
        severity=finding_severity,
        tech_stack=tech_stack,
        target_type=target_type,
        chain=chain,
        validated=True,
    )
