from __future__ import annotations

import asyncio
import json
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic_ai import Agent, RunContext, UsageLimits
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from mimick.agent.deps import MimickDeps, UNPRODUCTIVE_THRESHOLD
from mimick.agent.strategy import (
    extract_from_command,
    extract_from_tool_call,
    extract_url_from_command,
)
from mimick.config import settings
from mimick.llm.client import get_cache_settings, get_model
from mimick.logger import get_logger
from mimick.planner import AttackPlanner
from mimick.planner.models import Phase
from mimick.prompts.system import build_system_prompt, format_tool_descriptions
from mimick.tools import registry
from mimick.tools.base import ToolResult
from mimick.tracker import AttackTracker
from mimick.validation.validator import validate_findings

console = Console()
log = get_logger("agent")

_RECON_TOOLS = frozenset({"vuln_lookup", "wafw00f", "httpx", "subfinder"})

_FAILURE_ADVICE: dict[str, str] = {
    "sqli": "Try higher sqlmap level/risk, tamper scripts, or different injection points.",
    "xss": "Try different encoding, event handlers, or DOM-based vectors.",
    "vuln_scan": "Focus on manual testing instead of template scans.",
    "fuzzing": "Try different wordlists or switch to manual endpoint discovery.",
    "param_discovery": "Use browser JS analysis or manual parameter guessing.",
    "oob": "Check if outbound connections are blocked; try DNS-only exfil.",
}

_CATEGORY_QUERY_MAP: dict[str, tuple[str, str | None]] = {
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


def _make_run_id(target: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe = target.replace("://", "_").replace("/", "_").replace(".", "_")
    return f"mimick_{safe}_{ts}"


def _record_and_track(
    deps: MimickDeps,
    tool_name: str,
    args: dict[str, Any],
    stdout: str,
    stderr: str,
    success: bool,
) -> None:
    deps.findings.append(
        {
            "tool": tool_name,
            "args": args,
            "success": success,
            "output_lines": len(stdout.splitlines()),
        }
    )
    deps.tracker.record_tool_call(
        tool_name=tool_name,
        args=args,
        stdout=stdout,
        stderr=stderr,
        success=success,
        iteration=deps.iteration,
    )
    deps.tracker.save(settings.output_dir)


async def _run_tool(name: str, deps: MimickDeps, **kwargs: Any) -> str:
    tool = registry.get(name)
    if not tool:
        return f"Error: unknown tool '{name}'"
    if not tool.is_available():
        return f"Tool '{name}' is not installed. Skipping."

    log.info("Running [mimick.tool]%s[/] %s", name, json.dumps(kwargs, indent=None))

    try:
        result = await tool.run(**kwargs)
    except Exception as e:
        log.error("Tool [mimick.tool]%s[/] raised: %s", name, e)
        deps.record_attack_failure(
            name, kwargs.get("url") or kwargs.get("target") or ""
        )
        return f"Error executing {name}: {e}"

    if result.success:
        log.info(
            "[mimick.success]%s completed[/] (exit %d, %d lines)",
            name,
            result.return_code,
            len(result.stdout.splitlines()),
        )
    else:
        log.error(
            "[mimick.fail]%s failed[/] (exit %d): %s",
            name,
            result.return_code,
            result.stderr.strip()[:200],
        )
        deps.record_attack_failure(
            name, kwargs.get("url") or kwargs.get("target") or ""
        )

    _record_and_track(deps, name, kwargs, result.stdout, result.stderr, result.success)

    target_url = kwargs.get("url") or kwargs.get("target") or ""
    if target_url and name not in _RECON_TOOLS:
        strategy = extract_from_tool_call(name, kwargs)
        if strategy:
            deps.record_strategy(target_url, strategy)

    return result.summary()


async def _run_command(command: str, deps: MimickDeps) -> str:
    parts = shlex.split(command)
    tool_name = parts[0] if parts else "unknown"

    log.info("Running [mimick.tool]execute[/] %s", command)

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=300
        )
    except asyncio.TimeoutError:
        return f"Command timed out after 300s: {command[:100]}"
    except Exception as e:
        log.error("Execute failed: %s", e)
        deps.record_attack_failure(tool_name, "")
        return f"Error executing command: {e}"

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    return_code = proc.returncode or 0
    success = return_code == 0

    if success:
        log.info(
            "[mimick.success]%s completed[/] (exit %d, %d lines)",
            tool_name,
            return_code,
            len(stdout.splitlines()),
        )
    else:
        log.error(
            "[mimick.fail]%s failed[/] (exit %d): %s",
            tool_name,
            return_code,
            stderr.strip()[:200],
        )
        deps.record_attack_failure(tool_name, "")

    _record_and_track(deps, tool_name, {"command": command}, stdout, stderr, success)

    strategy = extract_from_command(command)
    if strategy:
        target_url = extract_url_from_command(command)
        if target_url:
            deps.record_strategy(target_url, strategy)

    return ToolResult(
        tool_name=tool_name,
        command=command,
        stdout=stdout,
        stderr=stderr,
        return_code=return_code,
    ).summary()


def _build_dynamic_context(deps: MimickDeps) -> str:
    sections: list[str] = []

    if deps.planner:
        deps.planner.perceive(deps.tracker, deps.iteration)
        directive = deps.planner.build_directive(deps.iteration)
        if directive:
            sections.append(directive)

    if deps.iteration < 2:
        return "\n\n".join(sections)

    sections.append("# Live Assessment Context (auto-updated each iteration)")

    tech = deps.tracker.get_tech_summary()
    if tech:
        lines = ["## Detected Tech Stack"] + [
            f"- **{host}**: {', '.join(techs)}"
            for host, techs in list(tech.items())[:10]
        ]
        sections.append("\n".join(lines))

    wafs = deps.tracker.get_waf_info()
    if wafs:
        sections.append(
            f"## WAF Detected\n- {', '.join(wafs)}\nAdjust payloads accordingly."
        )

    failures = deps.get_failure_summary()
    if failures:
        lines = ["## Attack Failures (adapt your strategy)"] + [
            f"- **{atype}** failed {count} time(s). {_FAILURE_ADVICE.get(atype, 'Try a different approach.')}"
            for atype, count in failures.items()
        ]
        sections.append("\n".join(lines))

    if deps._shared_child_findings:
        lines = ["## Child Agent Findings (do NOT duplicate)"] + [
            f"- [{f.get('severity', '?').upper()}] {f.get('title', '?')} at {f.get('url', '?')}"
            for f in deps._shared_child_findings[:20]
        ]
        sections.append("\n".join(lines))

    params = deps.tracker.get_discovered_params()
    if params:
        lines = ["## Discovered Parameters (test each for injection)"] + [
            f"- **{url}**: {', '.join(plist[:8])}"
            for url, plist in list(params.items())[:10]
        ]
        sections.append("\n".join(lines))

    endpoints = deps.tracker.get_discovered_endpoints()
    findings = deps.tracker.get_findings_summary()

    finding_urls = {f.get("url", "").rstrip("/").lower() for f in findings}
    strategy_urls = {url.lower().rstrip("/") for url in deps._strategies_tried}
    tested_set = finding_urls | strategy_urls

    untested_endpoints = (
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

    stuck = deps.get_stuck_targets(min_attempts=3)
    if stuck:
        lines = [
            "## Stuck Targets — Change Your Approach",
            "",
            "You have made 3+ attempts on these targets without a finding. "
            "**Pick a fundamentally different approach.**",
            "",
        ]
        for url, strategies in list(stuck.items())[:3]:
            unique = sorted(set(strategies))
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
    if not deps.planner:
        return
    active = deps.planner.tree.get_active_task()
    if not active or active.phase not in (
        Phase.VULN_HUNT,
        Phase.EXPLOIT,
        Phase.ESCALATE,
    ):
        return

    iters_on_task = deps.iteration - deps.planner.tree._active_since_iteration
    if iters_on_task < 3:
        return

    lookup = _CATEGORY_QUERY_MAP.get(active.category)
    if not lookup:
        return

    inject_key = f"{active.category}:{active.target_url}"
    if inject_key in deps._auto_injected_lookups:
        return
    deps._auto_injected_lookups.add(inject_key)

    query, subtopic = lookup

    tech_hint = ""
    for _host, techs in deps.tracker.get_tech_summary().items():
        tech_lower = " ".join(techs).lower()
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

    st_arg = subtopic or tech_hint
    lookup_call = f'vuln_lookup(query="{query}"'
    if st_arg:
        lookup_call += f', subtopic="{st_arg}"'
    lookup_call += ")"

    sections.append(
        f"## Hint: Stuck on `{active.category}` for {iters_on_task} iterations\n\n"
        f"**Call `{lookup_call}` NOW** for engine-specific payloads and bypass techniques."
    )


mimick_agent = Agent[MimickDeps, str](deps_type=MimickDeps, output_type=str)


@mimick_agent.instructions
async def system_instructions(ctx: RunContext[MimickDeps]) -> str:
    """Build the full system prompt with tools, scope, and dynamic context."""
    deps = ctx.deps
    if deps.iteration > 1:
        deps.update_productivity()

    tool_desc = format_tool_descriptions(registry.all(), is_child=deps.is_child)
    base = build_system_prompt(tool_desc, target=deps.target, scope=deps.scope)
    dynamic = _build_dynamic_context(deps)
    return f"{base}\n\n{dynamic}" if dynamic else base


@mimick_agent.tool
async def execute(ctx: RunContext[MimickDeps], command: str) -> str:
    """Execute a CLI command and return its output."""
    return await _run_command(command, ctx.deps)


@mimick_agent.tool
async def python_exec(ctx: RunContext[MimickDeps], code: str, timeout: int = 60) -> str:
    """Execute a Python script for complex logic, HTTP flows, or browser automation."""
    return await _run_tool("python_exec", ctx.deps, code=code, timeout=timeout)


@mimick_agent.tool
async def vuln_lookup(
    ctx: RunContext[MimickDeps], query: str, subtopic: str | None = None
) -> str:
    """Search the vulnerability knowledge base for payloads and techniques."""
    kwargs: dict[str, Any] = {"query": query}
    if subtopic:
        kwargs["subtopic"] = subtopic
    return await _run_tool("vuln_lookup", ctx.deps, **kwargs)


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
) -> str:
    """Report a confirmed vulnerability. Call immediately when you confirm a bug."""
    deps = ctx.deps

    if deps.tracker.is_duplicate_finding(url, title):
        return f"Duplicate finding (already reported): [{severity.upper()}] {title} at {url}"

    url_norm = url.rstrip("/").lower()
    title_norm = title.lower().strip()
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
            reflections = ""
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
        hints = f" Hints: {'; '.join(nxt.hints[-2:])}" if nxt.hints else ""
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

    hint_list = [h.strip() for h in hints.split(";") if h.strip()] if hints else []
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

    task = asyncio.create_task(
        _spawn_child(ctx.deps, target, prompt), name=f"child:{target}"
    )
    ctx.deps._child_tasks.append(task)

    _record_and_track(
        ctx.deps,
        "spawn_agent",
        {"target": target},
        f"Child agent spawned for {target}",
        "",
        True,
    )

    return f"Child agent spawned for {target}. {len(ctx.deps._child_tasks)} child(ren) running."


def _build_child_brief(parent_deps: MimickDeps, child_target: str) -> str:
    parts = [
        f"Perform a full web application security assessment on {child_target}.",
        f"This is a subdomain discovered during recon of {parent_deps.target}.",
    ]
    domain = urlparse(child_target).netloc

    _tech_focus: list[tuple[tuple[str, ...], str]] = [
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
        tech_lower = " ".join(techs).lower()
        focus = [
            label for keys, label in _tech_focus if any(k in tech_lower for k in keys)
        ]
        if focus:
            parts.append(f"Focus areas: {'; '.join(focus)}.")
        break

    wafs = parent_deps.tracker.get_waf_info()
    if wafs:
        parts.append(
            f"WAF detected: {', '.join(wafs)}. Use encoding and tamper scripts."
        )

    all_known = (
        parent_deps.tracker.get_findings_summary() + parent_deps._shared_child_findings
    )
    known_urls = {f.get("url", "") for f in all_known if domain in f.get("url", "")}
    if known_urls:
        parts.append(
            f"Already-found endpoints (skip): {', '.join(list(known_urls)[:5])}."
        )

    parts.append("Be thorough.")
    return " ".join(parts)


async def _spawn_child(
    parent_deps: MimickDeps, target: str, prompt: str
) -> dict[str, Any]:
    async with parent_deps.get_semaphore():
        child_log = get_logger(f"child.{target[:40]}")
        child_log.info("[mimick.phase]Child agent starting[/] for %s", target)

        try:
            _report, tracker = await run_agent(
                target=target,
                scope=parent_deps.scope,
                prompt=prompt,
                concurrency=parent_deps.concurrency,
                is_child=True,
                parent_deps=parent_deps,
            )
            child_findings = tracker.get_findings_summary()
            parent_deps._shared_child_findings.extend(child_findings)
            child_log.info(
                "[mimick.success]Child done[/] for %s — %d findings",
                target,
                len(child_findings),
            )
            return {
                "target": target,
                "status": "completed",
                "findings": len(child_findings),
            }
        except Exception as e:
            child_log.error("[mimick.fail]Child crashed[/] for %s: %s", target, e)
            return {"target": target, "status": "error", "findings": 0, "error": str(e)}


async def _wait_for_children(deps: MimickDeps) -> str:
    if not deps._child_tasks:
        return ""

    log.info("[mimick.phase]Waiting for %d child agent(s)[/]", len(deps._child_tasks))
    results = await asyncio.gather(*deps._child_tasks, return_exceptions=True)
    parts = [
        f"- Child error: {r}"
        if isinstance(r, Exception)
        else f"- {r.get('target', '?')}: {r.get('status', '?')}, {r.get('findings', 0)} finding(s)"
        for r in results
    ]
    deps._child_tasks.clear()
    return "\n".join(parts)


async def run_agent(
    target: str,
    scope: str | None = None,
    prompt: str | None = None,
    concurrency: int = 5,
    is_child: bool = False,
    parent_deps: MimickDeps | None = None,
    max_iterations: int | None = None,
) -> tuple[str, AttackTracker]:
    """Run the mimick pentesting agent."""
    scope = scope or target
    run_id = _make_run_id(target)
    max_iters = max_iterations or settings.max_iterations

    tracker = AttackTracker(
        run_id=run_id, target=target, scope=scope, prompt=prompt or ""
    )
    planner = AttackPlanner(target=target, scope=scope)
    deps = MimickDeps(
        target=target,
        scope=scope,
        tracker=tracker,
        run_id=run_id,
        is_child=is_child,
        concurrency=concurrency,
        planner=planner,
        _parent_deps=parent_deps,
    )
    model = get_model(settings.model)
    cache_settings = get_cache_settings(settings.model)
    user_prompt = (
        prompt
        or "Start the bug bounty assessment. Begin with recon, then discovery and vulnerability hunting."
    )

    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n[bold]Scope:[/bold] {scope}",
            title=f"[bold red]{'Child Agent' if is_child else 'Mimick'}[/bold red] - Web Pentest Agent",
            border_style="red",
        )
    )
    log.info("Tools: %d/%d installed", len(registry.available()), len(registry.all()))

    try:
        async with mimick_agent.iter(
            user_prompt,
            deps=deps,
            model=model,
            model_settings=cache_settings,
            usage_limits=UsageLimits(request_limit=max_iters),
        ) as agent_run:
            async for node in agent_run:
                if Agent.is_model_request_node(node):
                    deps.iteration += 1
                    log.info("[mimick.phase]--- Iteration %d ---[/]", deps.iteration)
                    console.rule(f"[bold]Iteration {deps.iteration}[/bold]")

                    if deps._unproductive_streak >= UNPRODUCTIVE_THRESHOLD * 2:
                        log.info(
                            "[mimick.phase]Early termination[/]: %d unproductive iters",
                            deps._unproductive_streak,
                        )
                        break

                elif Agent.is_call_tools_node(node):
                    if hasattr(node, "model_response"):
                        for part in node.model_response.parts:
                            if hasattr(part, "content") and not hasattr(
                                part, "tool_name"
                            ):
                                text = part.content
                                if text and text.strip():
                                    console.print()
                                    console.print(Markdown(text))
                                    console.print()
                                    tracker.record_reasoning(text, deps.iteration)
                                    tracker.save(settings.output_dir)

                        tool_names = [
                            p.tool_name
                            for p in node.model_response.parts
                            if hasattr(p, "tool_name")
                        ]
                        if tool_names:
                            log.info("Calling tools: %s", ", ".join(tool_names))

        report = (
            agent_run.result.output
            if agent_run.result
            else "Assessment complete (no report generated)."
        )

        if deps._child_tasks:
            children_summary = await _wait_for_children(deps)
            if children_summary:
                report += f"\n\n## Child Agent Results\n{children_summary}"

        log.info(
            "[mimick.success]Assessment complete[/] after %d iterations, %d tool calls",
            deps.iteration,
            len(deps.findings),
        )

        if not is_child:
            console.rule("[bold yellow]Validation Phase[/bold yellow]")
            validation_results = await validate_findings(tracker)
            if validation_results:
                report += _format_validation_section(validation_results)
                script_path = _write_validation_script(
                    tracker, validation_results, settings.output_dir, run_id
                )
                log.info("Validation script saved to %s", script_path)
            tracker.save(settings.output_dir)

        console.print(
            Panel(
                Markdown(report),
                title="[bold green]Assessment Complete[/bold green]",
                border_style="green",
            )
        )
        tracker.finish("completed")
        tracker.save(settings.output_dir)
        return report, tracker

    except Exception:
        for t in deps._child_tasks:
            t.cancel()
        tracker.finish("error")
        tracker.save(settings.output_dir)
        raise


def _format_validation_section(results: list[dict[str, str]]) -> str:
    status_icons = {"CONFIRMED": "✅", "UNCONFIRMED": "⚠️", "ERROR": "❌"}
    lines = [
        "\n\n## Validation Results\n",
        "| # | Severity | Finding | Status | Detail |",
        "|---|----------|---------|--------|--------|",
    ]
    for i, r in enumerate(results, 1):
        icon = status_icons.get(r["status"], "?")
        sev = r["severity"].upper() if r["severity"] else "—"
        lines.append(
            f"| {i} | {sev} | {r['title'][:50].replace('|', '\\|')} | {icon} {r['status']} | {r['detail'][:80].replace('|', '\\|')} |"
        )

    confirmed = sum(1 for r in results if r["status"] == "CONFIRMED")
    lines.append(
        f"\n**{confirmed}/{len(results)}** findings independently confirmed.\n"
    )
    return "\n".join(lines)


def _write_validation_script(
    tracker: AttackTracker,
    results: list[dict[str, str]],
    output_dir: Path,
    run_id: str,
) -> Path:
    findings_data = [
        {
            "id": node.id,
            "title": node.label,
            "severity": node.data.get("severity", ""),
            "url": node.data.get("url", ""),
            "reproduction": node.data.get("reproduction", []),
        }
        for node in tracker._nodes
        if node.type == "finding"
    ]

    findings_json = json.dumps(findings_data, indent=2).replace("\\", "\\\\")

    script = f'''\
#!/usr/bin/env python3
"""
Mimick — Finding Validation Script
====================================
Target:    {tracker.target}
Run ID:    {run_id}
Findings:  {len(findings_data)}

Replays the exact reproduction steps the agent used to confirm each
vulnerability.  No Mimick installation required — stdlib only.

Usage:
    python3 {run_id}_validate.py
    python3 {run_id}_validate.py --timeout 20
"""

import json, re, ssl, sys, time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

TIMEOUT = 12

FINDINGS = json.loads("""
{findings_json}
""")

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

RED, GREEN, YELLOW, BOLD, RESET = "\\033[91m", "\\033[92m", "\\033[93m", "\\033[1m", "\\033[0m"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http(url, method="GET", headers=None, body=None):
    data = body.encode() if body else None
    req = Request(url, method=method, data=data)
    for k, v in (headers or {{}}).items():
        req.add_header(k, v)
    opener = build_opener(HTTPSHandler(context=_CTX), _NoRedirect)
    try:
        resp = opener.open(req, timeout=TIMEOUT)
        rbody = resp.read().decode(errors="replace")
        rhdrs = {{k.lower(): v for k, v in resp.getheaders()}}
        return resp.status, rhdrs, rbody
    except HTTPError as e:
        rbody = e.read().decode(errors="replace") if e.fp else ""
        rhdrs = {{k.lower(): v for k, v in e.headers.items()}}
        return e.code, rhdrs, rbody
    except URLError as e:
        if hasattr(e, "code"):
            rbody = e.read().decode(errors="replace") if hasattr(e, "read") else ""
            rhdrs = {{k.lower(): v for k, v in e.headers.items()}} if hasattr(e, "headers") else {{}}
            return e.code, rhdrs, rbody
        raise


def extract_cookies(resp_hdrs):
    raw = resp_hdrs.get("set-cookie", "")
    if not raw:
        return {{}}
    parts = re.split(r",\\s*(?=[A-Za-z_][A-Za-z0-9_]*=)", raw)
    return {{nv.split("=", 1)[0].strip(): nv.split("=", 1)[1].strip()
             for part in parts
             for nv in [part.split(";")[0].strip()]
             if "=" in nv}}


_PLACEHOLDER_RE = re.compile(r"REPLACE[_A-Z]*", re.IGNORECASE)


def inject_cookies(headers, session_cookies):
    if not session_cookies:
        return
    cookie_val = "; ".join(f"{{k}}={{v}}" for k, v in session_cookies.items())
    cookie_key = next((k for k in headers if k.lower() == "cookie"), None)
    if cookie_key is None:
        headers["Cookie"] = cookie_val
    elif _PLACEHOLDER_RE.search(headers[cookie_key]):
        headers[cookie_key] = cookie_val


def check_expect(expect, status, headers, body):
    passed, failed = [], []
    checks = [
        ("status", lambda: status == expect["status"], lambda: f"status {{status}} (want {{expect['status']}})"),
        ("body_contains", lambda: expect["body_contains"] in body, lambda: f"body {{'contains' if expect['body_contains'] in body else 'missing'}} '{{expect['body_contains'][:40]}}'"),
        ("body_not_contains", lambda: expect["body_not_contains"] not in body, lambda: f"body '{{expect['body_not_contains'][:40]}}' {{'absent' if expect['body_not_contains'] not in body else 'present'}}'"),
        ("header_absent", lambda: expect["header_absent"].lower() not in headers, lambda: f"header '{{expect['header_absent']}}' {{'absent' if expect['header_absent'].lower() not in headers else 'present'}}'"),
        ("header_present", lambda: expect["header_present"].lower() in headers, lambda: f"header '{{expect['header_present']}}' {{'present' if expect['header_present'].lower() in headers else 'absent'}}'"),
        ("status_not", lambda: status != expect["status_not"], lambda: f"status {{status}} (not {{expect['status_not']}})"),
        ("min_body_length", lambda: len(body) >= expect["min_body_length"], lambda: f"body {{len(body)}}B (min {{expect['min_body_length']}})"),
    ]
    for key, test_fn, msg_fn in checks:
        if key in expect:
            (passed if test_fn() else failed).append(msg_fn())
    if "header_contains" in expect:
        for hname, want in expect["header_contains"].items():
            actual = headers.get(hname.lower(), "")
            ok = want.lower() in actual.lower()
            (passed if ok else failed).append(f"{{hname}}={{'ok' if ok else repr(actual[:40])}}")
    return (False, "; ".join(failed)) if failed else (True, "; ".join(passed) if passed else "ok")


def validate(finding):
    steps = finding.get("reproduction") or []
    if not steps:
        return "SKIPPED", "no reproduction steps"
    details, last_passed, session_cookies = [], False, {{}}
    for i, step in enumerate(steps, 1):
        try:
            hdrs = dict(step.get("headers") or {{}})
            inject_cookies(hdrs, session_cookies)
            s, h, b = http(step.get("url", ""), step.get("method", "GET"), hdrs, step.get("body"))
            session_cookies.update(extract_cookies(h))
            p, d = check_expect(step.get("expect", {{}}), s, h, b)
        except Exception as e:
            p, d = False, str(e)
        prefix = f"step {{i}}: " if len(steps) > 1 else ""
        details.append(f"{{prefix}}{{d}}")
        last_passed = p
    return ("CONFIRMED" if last_passed else "UNCONFIRMED"), "; ".join(details)


def main():
    if "--timeout" in sys.argv:
        i = sys.argv.index("--timeout")
        if i + 1 < len(sys.argv):
            global TIMEOUT
            TIMEOUT = int(sys.argv[i + 1])

    print(f"\\n{{BOLD}}Mimick Finding Validator{{RESET}}")
    print(f"Target:   {tracker.target}")
    print(f"Findings: {{len(FINDINGS)}}\\n")
    print("-" * 72)

    confirmed = 0
    for i, f in enumerate(FINDINGS, 1):
        try:
            status, detail = validate(f)
        except Exception as e:
            status, detail = "ERROR", str(e)

        if status == "CONFIRMED":
            icon, color = "✅", GREEN
            confirmed += 1
        elif status == "SKIPPED":
            icon, color = "⏭️ ", YELLOW
        elif status == "UNCONFIRMED":
            icon, color = "⚠️ ", YELLOW
        else:
            icon, color = "❌", RED

        sev = f["severity"].upper()
        print(f"  {{color}}{{icon}} [{{sev:>8}}] {{f['title'][:55]}}{{RESET}}")
        print(f"           {{status}}: {{detail[:80]}}")
        time.sleep(0.3)

    print("-" * 72)
    total = len(FINDINGS)
    skipped = sum(1 for f in FINDINGS if not f.get("reproduction"))
    testable = total - skipped
    print(f"\\n{{BOLD}}{{confirmed}}/{{testable}} testable findings confirmed")
    if skipped:
        print(f"{{skipped}} finding(s) skipped (no reproduction steps){{RESET}}")
    if confirmed < testable:
        print(f"{{YELLOW}}{{testable - confirmed}} finding(s) could not be auto-confirmed.{{RESET}}")
    print()
    sys.exit(0 if confirmed == testable else 1)


if __name__ == "__main__":
    main()
'''

    val_dir = output_dir / "validation"
    val_dir.mkdir(parents=True, exist_ok=True)
    script_path = val_dir / f"{run_id}_validate.py"
    script_path.write_text(script)
    script_path.chmod(0o755)
    return script_path
