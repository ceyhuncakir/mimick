"""Extract experience records from attack tracker state."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from mimick.memory.models import ChainStep, Experience
from mimick.tracker import AttackTracker


def _detect_target_type(tracker: AttackTracker) -> str:
    """Infer the target type from discovered assets.

    Args:
        tracker: Attack tracker with accumulated discovery data.

    Returns:
        One of ``"spa"``, ``"web_api"``, or ``"web_app"``.
    """
    endpoints: list[str] = tracker.get_discovered_endpoints()
    tech: dict[str, list[str]] = tracker.get_tech_summary()

    all_tech: str = " ".join(" ".join(v) for v in tech.values()).lower()

    if any(kw in all_tech for kw in ("react", "vue", "angular", "next")):
        return "spa"
    if any("/api/" in ep.lower() for ep in endpoints):
        return "web_api"
    return "web_app"


def _extract_tech_stack(tracker: AttackTracker) -> list[str]:
    """Extract a deduplicated flat list of technologies from the tracker.

    Args:
        tracker: Attack tracker with accumulated discovery data.

    Returns:
        Up to 10 normalized technology names.
    """
    tech_map: dict[str, list[str]] = tracker.get_tech_summary()
    seen: set[str] = set()
    result: list[str] = []
    for techs in tech_map.values():
        for t in techs:
            clean: str = t.replace("Server: ", "").strip().lower()
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

    Captures what the agent saw leading up to the finding: tech stack,
    endpoints, WAF info, parameters, and reasoning snippets.

    Args:
        tracker: Attack tracker with accumulated discovery data.
        finding_title: Title of the finding.
        finding_url: URL where the vulnerability was found.
        finding_iteration: Iteration number when the finding occurred.

    Returns:
        Multi-line observation string, or a fallback if no data is
        available.
    """
    parts: list[str] = []

    tech: dict[str, list[str]] = tracker.get_tech_summary()
    if tech:
        tech_lines: list[str] = [
            f"{host}: {', '.join(ts)}" for host, ts in list(tech.items())[:5]
        ]
        parts.append(f"Tech stack: {'; '.join(tech_lines)}")

    wafs: list[str] = tracker.get_waf_info()
    if wafs:
        parts.append(f"WAF: {', '.join(wafs)}")

    endpoints: list[str] = tracker.get_discovered_endpoints()
    if endpoints:
        relevant: list[str] = [ep for ep in endpoints if _url_overlap(ep, finding_url)]
        if not relevant:
            relevant = endpoints[:5]
        parts.append(f"Endpoints: {', '.join(relevant[:5])}")

    params: dict[str, list[str]] = tracker.get_discovered_params()
    if params:
        param_strs: list[str] = [
            f"{url}: {', '.join(ps[:5])}" for url, ps in list(params.items())[:3]
        ]
        parts.append(f"Params: {'; '.join(param_strs)}")

    reasoning_context: str = _extract_reasoning_before(tracker, finding_iteration)
    if reasoning_context:
        parts.append(f"Agent observations: {reasoning_context}")

    return "\n".join(parts) if parts else f"Finding at {finding_url}"


def _url_overlap(ep: str, finding_url: str) -> bool:
    """Check whether two URLs share at least two path segments.

    Args:
        ep: An endpoint URL.
        finding_url: The finding URL to compare against.

    Returns:
        ``True`` if the URLs share a common path prefix of at least two
        segments.
    """
    try:
        ep_path: str = urlparse(ep).path.rstrip("/")
        finding_path: str = urlparse(finding_url).path.rstrip("/")
        if not ep_path or not finding_path:
            return False
        ep_parts: list[str] = ep_path.split("/")
        find_parts: list[str] = finding_path.split("/")
        common: int = sum(1 for a, b in zip(ep_parts, find_parts) if a == b)
        return common >= 2
    except Exception:
        return False


def _extract_reasoning_before(
    tracker: AttackTracker,
    finding_iteration: int,
    max_chars: int = 300,
) -> str:
    """Extract key reasoning snippets from events before the finding.

    Args:
        tracker: Attack tracker containing event history.
        finding_iteration: Iteration number of the finding.
        max_chars: Maximum character length for the returned string.

    Returns:
        Pipe-separated reasoning excerpts, truncated to *max_chars*.
    """
    reasoning_parts: list[str] = []
    for event in tracker._events:
        if event.get("iteration", 0) > finding_iteration:
            break
        if event.get("type") == "reasoning":
            text: str = event.get("text", "")
            first_line: str = text.split("\n")[0].strip()
            if first_line and len(first_line) > 20:
                reasoning_parts.append(first_line[:100])

    recent: list[str] = reasoning_parts[-3:]
    result: str = " | ".join(recent)
    return result[:max_chars]


def _build_chain(
    tracker: AttackTracker,
    finding_iteration: int,
) -> list[ChainStep]:
    """Extract the tool-call chain leading to a finding.

    Only includes events after the previous finding to avoid
    contaminating the chain with a different exploit's steps.

    Args:
        tracker: Attack tracker containing event history.
        finding_iteration: Iteration number of the current finding.

    Returns:
        Ordered list of up to 15 chain steps.
    """
    prev_finding_iter: int = 0
    for event in tracker._events:
        if (
            event.get("type") == "finding"
            and event.get("iteration", 0) < finding_iteration
        ):
            prev_finding_iter = event["iteration"]

    tool_events: list[dict[str, Any]] = [
        e
        for e in tracker._events
        if e.get("type") == "tool_call"
        and prev_finding_iter < e.get("iteration", 0) <= finding_iteration
    ]

    relevant: list[dict[str, Any]] = tool_events[-15:]

    chain: list[ChainStep] = []
    for event in relevant:
        tool: str = event.get("tool", "")
        args: dict[str, Any] | str = event.get("args", {})

        if isinstance(args, dict):
            arg_parts: list[str] = [f"{k}={v}" for k, v in args.items() if v]
            args_str: str = ", ".join(arg_parts)
        else:
            args_str = str(args)

        stdout: str = event.get("stdout", "")
        result_summary: str = _summarize_output(tool, stdout)

        chain.append(
            ChainStep(
                tool=tool,
                args=args_str[:200],
                result_summary=result_summary,
            )
        )

    return chain


def _summarize_output(tool: str, stdout: str, max_len: int = 150) -> str:
    """Create a compact summary of a tool's output.

    Args:
        tool: Name of the tool that produced the output.
        stdout: Raw standard output from the tool.
        max_len: Maximum length for the first-line fallback summary.

    Returns:
        A short human-readable summary string.
    """
    if not stdout:
        return "(no output)"

    lines: list[str] = stdout.strip().splitlines()
    line_count: int = len(lines)

    if tool in ("httpx", "nuclei", "ffuf", "dalfox"):
        return f"{line_count} results"
    if tool == "subfinder":
        return f"{line_count} subdomains"
    if tool == "nmap":
        ports: list[str] = re.findall(r"(\d+/\w+)\s+open", stdout)
        if ports:
            return f"Open ports: {', '.join(ports[:5])}"

    first: str = lines[0].strip()[:max_len]
    if line_count > 1:
        return f"{first} (+{line_count - 1} lines)"
    return first


def _build_strategy(
    title: str,
    description: str,
    chain: list[ChainStep],
) -> str:
    """Build a concise strategy string from the finding and chain.

    Args:
        title: Finding title.
        description: Finding description text.
        chain: Tool-call chain associated with the finding.

    Returns:
        Strategy string truncated to 500 characters.
    """
    tool_flow: str = " → ".join(step.tool for step in chain[-6:])

    parts: list[str] = [f"{title}."]
    if description:
        first_sentence: str = description.split(".")[0].strip()
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

    Args:
        tracker: Attack tracker with accumulated state.
        finding_title: Short title of the vulnerability.
        finding_severity: Severity level string.
        finding_url: URL where the vulnerability was found.
        finding_description: Detailed description of the finding.
        finding_iteration: Iteration number when the finding occurred.
        vuln_type: Vulnerability category provided by the agent.

    Returns:
        A fully populated Experience instance ready for storage.
    """
    tech_stack: list[str] = _extract_tech_stack(tracker)
    target_type: str = _detect_target_type(tracker)
    observation: str = _build_observation(
        tracker, finding_title, finding_url, finding_iteration
    )
    chain: list[ChainStep] = _build_chain(tracker, finding_iteration)

    strategy: str = _build_strategy(finding_title, finding_description, chain)

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
