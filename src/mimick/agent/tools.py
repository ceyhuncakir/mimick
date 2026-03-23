from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from pydantic_ai import RunContext

from mimick.agent.core import mimick_agent, run_tool, run_command, record_and_track
from mimick.agent.deps import MimickDeps
from mimick.config import settings
from mimick.logger import get_logger
from mimick.memory.extractor import extract_experience
from mimick.memory.linker import auto_link
from mimick.memory.store import ExperienceStore

log = get_logger("agent.tools")

_experience_store: ExperienceStore | None = None


def _get_experience_store() -> ExperienceStore | None:
    """Lazily initialize the global experience store.

    Returns:
        The singleton experience store, or ``None`` if disabled or
        initialization fails.
    """
    global _experience_store
    if not settings.experience_enabled:
        return None
    if _experience_store is None:
        try:
            _experience_store = ExperienceStore(settings.experience_db_dir)
        except Exception as e:
            log.warning("Failed to initialize experience store: %s", e)
            return None
    return _experience_store


@mimick_agent.tool
async def execute(ctx: RunContext[MimickDeps], command: str) -> str:
    """Execute a CLI command and return its output."""
    return await run_command(command, ctx.deps)


@mimick_agent.tool
async def python_exec(ctx: RunContext[MimickDeps], code: str, timeout: int = 60) -> str:
    """Execute a Python script for complex logic, HTTP flows, or browser automation."""
    return await run_tool("python_exec", ctx.deps, code=code, timeout=timeout)


@mimick_agent.tool
async def vuln_lookup(
    ctx: RunContext[MimickDeps], query: str, subtopic: str | None = None
) -> str:
    """Search the vulnerability knowledge base for payloads and techniques."""
    kwargs: dict[str, Any] = {"query": query}
    if subtopic:
        kwargs["subtopic"] = subtopic
    return await run_tool("vuln_lookup", ctx.deps, **kwargs)


@mimick_agent.tool
async def recall_experience(
    ctx: RunContext[MimickDeps],
    observation: str,
    vuln_type: str | None = None,
) -> str:
    """Query past validated exploitation chains that match your current observation.

    Call this when you discover something interesting that you want to
    cross-reference against past successful attacks — e.g. a new tech stack,
    unusual response behaviour, a parameter pattern, or before starting a new
    attack phase.

    Args:
        observation: Describe what you're seeing right now — tech stack,
            endpoint patterns, response anomalies, parameter names, WAF
            behaviour, etc.  The richer the description, the better the match.
        vuln_type: Optional vulnerability class filter (e.g. "sqli", "xss",
            "idor", "ssti").  Omit to search across all classes.
    """
    store: ExperienceStore | None = _get_experience_store()
    if not store or store.count() == 0:
        return "No past experiences available yet."

    experiences = store.query(
        observation=observation,
        top_k=settings.experience_top_k,
        vuln_type=vuln_type,
    )
    if not experiences:
        return "No matching past experiences found for this observation."

    return store.format_experiences_for_prompt(experiences)


@mimick_agent.tool
async def report_finding(
    ctx: RunContext[MimickDeps],
    title: str,
    severity: str,
    url: str,
    description: str,
    proof: str,
    reproduction: list[dict[str, Any]] | None = None,
    impact: str = "",
    remediation: str = "",
    vuln_type: str = "",
) -> str:
    """Report a confirmed vulnerability. Call immediately when you confirm a bug."""
    deps: MimickDeps = ctx.deps

    if deps.tracker.is_duplicate_finding(url, title):
        return f"Duplicate finding (already reported): [{severity.upper()}] {title} at {url}"

    url_norm: str = url.rstrip("/").lower()
    title_norm: str = title.lower().strip()
    for cf in deps._shared_child_findings:
        if (
            cf.get("url", "").rstrip("/").lower() == url_norm
            and cf.get("title", "").lower().strip() == title_norm
        ):
            return f"Duplicate finding (child reported): [{severity.upper()}] {title} at {url}"

    log.info("[mimick.fail][%s] Finding: %s[/] at %s", severity.upper(), title, url)

    deps.tracker.record_finding(
        title=title,
        severity=severity,
        url=url,
        description=description,
        proof=proof,
        reproduction=reproduction or [],
        impact=impact,
        remediation=remediation,
        iteration=deps.iteration,
        vuln_type=vuln_type,
    )
    deps.tracker.save(settings.output_dir)
    deps.findings.append(
        {
            "tool": "report_finding",
            "args": {"title": title, "severity": severity, "url": url},
            "success": True,
            "output_lines": 0,
        }
    )

    store: ExperienceStore | None = _get_experience_store()
    if store:

        def _capture() -> None:
            try:
                experience = extract_experience(
                    tracker=deps.tracker,
                    finding_title=title,
                    finding_severity=severity,
                    finding_url=url,
                    finding_description=description,
                    finding_iteration=deps.iteration,
                    vuln_type=vuln_type,
                )
                store.add(experience)
                auto_link(store, experience)
            except Exception as e:
                log.debug("Experience capture failed: %s", e)

        asyncio.get_event_loop().run_in_executor(None, _capture)

    return f"Finding recorded: [{severity.upper()}] {title} at {url}"


@mimick_agent.tool
async def plan_next(
    ctx: RunContext[MimickDeps], status: str = "completed", note: str = ""
) -> str:
    """Signal the planner that the current task is done and get the next one."""
    planner = ctx.deps.planner
    if not planner:
        return "No planner active."

    active = planner.tree.get_active_task()
    if not active:
        return "No active task. Continue with your assessment."

    if status == "completed":
        planner.complete_current(note)
    elif status == "skipped":
        planner.skip_current(note)
    elif status == "failed":
        if planner.fail_current(note):
            stree = planner.get_active_search_tree()
            new_approach = stree.get_active() if stree else None
            remaining = stree.remaining_count() if stree else 0
            desc = new_approach.description if new_approach else "next approach"
            reflections: str = ""
            if stree:
                failed = [
                    a
                    for a in stree._approaches
                    if a.status.value == "failed" and a.reflection
                ]
                if failed:
                    reflections = " Lessons: " + "; ".join(
                        f"'{a.description}': {a.reflection}" for a in failed[-2:]
                    )
            return f"BACKTRACKING to: {desc} ({remaining} remaining).{reflections}"
    else:
        return f"Unknown status '{status}'. Use 'completed', 'skipped', or 'failed'."

    nxt = planner.next_task(ctx.deps.iteration)
    if nxt:
        hints: str = f" Hints: {'; '.join(nxt.hints[-2:])}" if nxt.hints else ""
        return f"Task '{active.category}' → {status}. Next: [{nxt.category}] {nxt.description}{hints}"
    return f"Task '{active.category}' → {status}. No more planned tasks."


@mimick_agent.tool
async def create_task(
    ctx: RunContext[MimickDeps],
    category: str,
    target_url: str,
    description: str,
    priority: int,
    phase: str = "vuln_hunt",
    hints: str = "",
) -> str:
    """Create a new attack task based on your observations."""
    planner = ctx.deps.planner
    if not planner:
        return "No planner active."

    hint_list: list[str] = (
        [h.strip() for h in hints.split(";") if h.strip()] if hints else []
    )
    node = planner.create_task(
        category=category,
        target_url=target_url,
        description=description,
        priority=priority,
        phase=phase,
        hints=hint_list,
        iteration=ctx.deps.iteration,
    )
    if node:
        return f"Task created: [{node.category}] {node.description} (priority={node.priority})"
    return (
        f"Task exists for {category} on {target_url} (priority may have been boosted)."
    )


@mimick_agent.tool
async def spawn_agent(
    ctx: RunContext[MimickDeps], target: str, prompt: str | None = None
) -> str:
    """Spawn a child agent to independently pentest a subdomain/URL."""
    if ctx.deps.is_child:
        return "Error: child agents cannot spawn more agents."

    if not target.startswith("http"):
        target = f"https://{target}"

    if not prompt:
        prompt = _build_child_brief(ctx.deps, target)

    log.info("[mimick.phase]Spawning child agent[/] for [mimick.target]%s[/]", target)

    from mimick.agent.runner import spawn_child

    task: asyncio.Task[dict[str, Any]] = asyncio.create_task(
        spawn_child(ctx.deps, target, prompt), name=f"child:{target}"
    )
    ctx.deps._child_tasks.append(task)

    record_and_track(
        ctx.deps,
        "spawn_agent",
        {"target": target},
        f"Child agent spawned for {target}",
        "",
        True,
    )

    return f"Child agent spawned for {target}. {len(ctx.deps._child_tasks)} child(ren) running."


def _build_child_brief(parent_deps: MimickDeps, child_target: str) -> str:
    """Build an initial prompt for a child agent.

    Args:
        parent_deps: The parent agent's dependencies.
        child_target: The URL the child agent will assess.

    Returns:
        A prompt string with target context and focus areas.
    """
    parts: list[str] = [
        f"Perform a full web application security assessment on {child_target}.",
        f"This is a subdomain discovered during recon of {parent_deps.target}.",
    ]
    domain: str = urlparse(child_target).netloc

    tech_focus: list[tuple[tuple[str, ...], str]] = [
        (
            ("php", "laravel", "wordpress", "apache"),
            "PHP-specific vulns (LFI, RCE, SQLi)",
        ),
        (("node", "express", "next"), "prototype pollution, SSRF, NoSQL injection"),
        (("java", "spring", "tomcat"), "deserialization, SSTI, XXE"),
        (("python", "django", "flask"), "SSTI, command injection, path traversal"),
        (("angular", "react", "vue"), "DOM XSS, CSTI, client-side vulns"),
    ]
    for host, techs in parent_deps.tracker.get_tech_summary().items():
        if domain not in host:
            continue
        parts.append(f"Detected tech stack: {', '.join(techs)}.")
        tech_lower: str = " ".join(techs).lower()
        focus: list[str] = [
            label for keys, label in tech_focus if any(k in tech_lower for k in keys)
        ]
        if focus:
            parts.append(f"Focus areas: {'; '.join(focus)}.")
        break

    wafs: list[str] = parent_deps.tracker.get_waf_info()
    if wafs:
        parts.append(
            f"WAF detected: {', '.join(wafs)}. Use encoding and tamper scripts."
        )

    all_known: list[dict[str, Any]] = (
        parent_deps.tracker.get_findings_summary() + parent_deps._shared_child_findings
    )
    known_urls: set[str] = {
        f.get("url", "") for f in all_known if domain in f.get("url", "")
    }
    if known_urls:
        parts.append(
            f"Already-found endpoints (skip): {', '.join(list(known_urls)[:5])}."
        )

    parts.append("Be thorough.")
    return " ".join(parts)
