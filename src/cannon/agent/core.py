"""Core agent built on PydanticAI for orchestrating pentesting tools."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic_ai import Agent, RunContext, UsageLimits
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from cannon.config import settings
from cannon.llm.client import get_model
from cannon.logger import get_logger
from cannon.prompts.system import build_system_prompt, format_tool_descriptions
from cannon.tools import registry
from cannon.tracker import AttackTracker

console = Console()
log = get_logger("agent")


# ── Dependencies ──────────────────────────────────────────────────────

@dataclass
class CannonDeps:
    """Dependencies injected into every tool call."""

    target: str
    scope: str
    tracker: AttackTracker
    run_id: str
    is_child: bool = False
    concurrency: int = 5
    iteration: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)

    # Child agent management (only root agent uses these)
    _semaphore: asyncio.Semaphore | None = field(default=None, repr=False)
    _child_tasks: list[asyncio.Task] = field(default_factory=list, repr=False)
    _parent_deps: CannonDeps | None = field(default=None, repr=False)

    def get_semaphore(self) -> asyncio.Semaphore:
        """Get or create the shared semaphore (root agent owns it)."""
        if self._parent_deps:
            return self._parent_deps.get_semaphore()
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)
        return self._semaphore


# ── Helpers ───────────────────────────────────────────────────────────

def _make_run_id(target: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe = target.replace("://", "_").replace("/", "_").replace(".", "_")
    return f"cannon_{safe}_{ts}"


async def _run_tool(name: str, deps: CannonDeps, **kwargs: Any) -> str:
    """Look up a CLI tool by name, execute it, record in tracker, return summary."""
    tool = registry.get(name)
    if not tool:
        return f"Error: unknown tool '{name}'"
    if not tool.is_available():
        return f"Tool '{name}' is not installed. Skipping."

    log.info("Running [cannon.tool]%s[/] %s", name, json.dumps(kwargs, indent=None))

    try:
        result = await tool.run(**kwargs)
    except Exception as e:
        log.error("Tool [cannon.tool]%s[/] raised: %s", name, e)
        return f"Error executing {name}: {e}"

    if result.success:
        log.info(
            "[cannon.success]%s completed[/] (exit %d, %d lines)",
            name, result.return_code, len(result.stdout.splitlines()),
        )
    else:
        log.error(
            "[cannon.fail]%s failed[/] (exit %d): %s",
            name, result.return_code, result.stderr.strip()[:200],
        )

    deps.findings.append({
        "tool": name, "args": kwargs,
        "success": result.success,
        "output_lines": len(result.stdout.splitlines()),
    })

    deps.tracker.record_tool_call(
        tool_name=name, args=kwargs,
        stdout=result.stdout, stderr=result.stderr,
        success=result.success, iteration=deps.iteration,
    )
    deps.tracker.save(settings.output_dir)

    return result.summary()


# ── Build the PydanticAI agent ────────────────────────────────────────

cannon_agent = Agent[CannonDeps, str](
    deps_type=CannonDeps,
    output_type=str,
)


@cannon_agent.instructions
async def system_instructions(ctx: RunContext[CannonDeps]) -> str:
    """Build the full system prompt with tools and scope."""
    tool_desc = format_tool_descriptions(registry.all(), is_child=ctx.deps.is_child)
    return build_system_prompt(tool_desc, target=ctx.deps.target, scope=ctx.deps.scope)


# ── Tool registrations ────────────────────────────────────────────────
# Each wraps the existing CLI tool via _run_tool()


@cannon_agent.tool
async def subfinder(
    ctx: RunContext[CannonDeps],
    domain: str,
    recursive: bool = False,
    sources: str | None = None,
) -> str:
    """Passive subdomain enumeration. Discovers subdomains of a target domain."""
    kwargs: dict[str, Any] = {"domain": domain, "recursive": recursive}
    if sources:
        kwargs["sources"] = sources
    return await _run_tool("subfinder", ctx.deps, **kwargs)


@cannon_agent.tool
async def httpx(
    ctx: RunContext[CannonDeps],
    target: str | None = None,
    list: str | None = None,
    status_code: bool = True,
    title: bool = True,
    tech_detect: bool = False,
    web_server: bool = False,
    follow_redirects: bool = True,
    ports: str | None = None,
) -> str:
    """HTTP toolkit for probing URLs. Checks alive hosts, status codes, titles, tech."""
    kwargs: dict[str, Any] = {
        "status_code": status_code, "title": title,
        "tech_detect": tech_detect, "web_server": web_server,
        "follow_redirects": follow_redirects,
    }
    if target:
        kwargs["target"] = target
    if list:
        kwargs["list"] = list
    if ports:
        kwargs["ports"] = ports
    return await _run_tool("httpx", ctx.deps, **kwargs)


@cannon_agent.tool
async def nuclei(
    ctx: RunContext[CannonDeps],
    target: str | None = None,
    list: str | None = None,
    templates: str | None = None,
    tags: str | None = None,
    severity: str | None = None,
    rate_limit: int = 150,
    automatic_scan: bool = False,
) -> str:
    """Fast vulnerability scanner with YAML templates. Scans for CVEs, misconfigs, etc."""
    kwargs: dict[str, Any] = {"rate_limit": rate_limit, "automatic_scan": automatic_scan}
    if target:
        kwargs["target"] = target
    if list:
        kwargs["list"] = list
    if templates:
        kwargs["templates"] = templates
    if tags:
        kwargs["tags"] = tags
    if severity:
        kwargs["severity"] = severity
    return await _run_tool("nuclei", ctx.deps, **kwargs)


@cannon_agent.tool
async def ffuf(
    ctx: RunContext[CannonDeps],
    url: str,
    wordlist: str,
    method: str = "GET",
    headers: list[str] | None = None,
    filter_code: str | None = None,
    match_code: str | None = None,
    filter_size: str | None = None,
    threads: int = 40,
    rate: int | None = None,
    extensions: str | None = None,
    data: str | None = None,
    recursion: bool = False,
) -> str:
    """Fast web fuzzer. Discovers hidden dirs, files, params with FUZZ keyword in URL."""
    kwargs: dict[str, Any] = {
        "url": url, "wordlist": wordlist, "method": method,
        "threads": threads, "recursion": recursion,
    }
    if headers:
        kwargs["headers"] = headers
    if filter_code:
        kwargs["filter_code"] = filter_code
    if match_code:
        kwargs["match_code"] = match_code
    if filter_size:
        kwargs["filter_size"] = filter_size
    if rate is not None:
        kwargs["rate"] = rate
    if extensions:
        kwargs["extensions"] = extensions
    if data:
        kwargs["data"] = data
    return await _run_tool("ffuf", ctx.deps, **kwargs)


@cannon_agent.tool
async def nmap(
    ctx: RunContext[CannonDeps],
    target: str,
    ports: str | None = None,
    top_ports: int | None = None,
    scan_type: str = "connect",
    service_detection: bool = True,
    os_detection: bool = False,
    scripts: str | None = None,
    timing: int = 4,
) -> str:
    """Network scanner for port discovery and service/version detection."""
    kwargs: dict[str, Any] = {
        "target": target, "scan_type": scan_type,
        "service_detection": service_detection,
        "os_detection": os_detection, "timing": timing,
    }
    if ports:
        kwargs["ports"] = ports
    if top_ports is not None:
        kwargs["top_ports"] = top_ports
    if scripts:
        kwargs["scripts"] = scripts
    return await _run_tool("nmap", ctx.deps, **kwargs)


@cannon_agent.tool
async def katana(
    ctx: RunContext[CannonDeps],
    target: str | None = None,
    list: str | None = None,
    depth: int = 3,
    js_crawl: bool = True,
    headless: bool = False,
    scope: str | None = None,
    extensions_filter: str | None = None,
) -> str:
    """Fast web crawler. Discovers URLs, endpoints, and JS files."""
    kwargs: dict[str, Any] = {
        "depth": depth, "js_crawl": js_crawl, "headless": headless,
    }
    if target:
        kwargs["target"] = target
    if list:
        kwargs["list"] = list
    if scope:
        kwargs["scope"] = scope
    if extensions_filter:
        kwargs["extensions_filter"] = extensions_filter
    return await _run_tool("katana", ctx.deps, **kwargs)


@cannon_agent.tool
async def wafw00f(
    ctx: RunContext[CannonDeps],
    target: str,
    scan_all: bool = False,
) -> str:
    """Detect Web Application Firewalls (WAFs) protecting a target."""
    return await _run_tool("wafw00f", ctx.deps, target=target, scan_all=scan_all)


@cannon_agent.tool
async def curl(
    ctx: RunContext[CannonDeps],
    url: str,
    method: str = "GET",
    headers: list[str] | None = None,
    data: str | None = None,
    follow_redirects: bool = False,
    user_agent: str | None = None,
    cookie: str | None = None,
    proxy: str | None = None,
    insecure: bool = False,
    max_time: int = 30,
) -> str:
    """Make HTTP requests. Supports all methods, headers, data, cookies, proxies."""
    kwargs: dict[str, Any] = {
        "url": url, "method": method,
        "follow_redirects": follow_redirects,
        "insecure": insecure, "max_time": max_time,
    }
    if headers:
        kwargs["headers"] = headers
    if data:
        kwargs["data"] = data
    if user_agent:
        kwargs["user_agent"] = user_agent
    if cookie:
        kwargs["cookie"] = cookie
    if proxy:
        kwargs["proxy"] = proxy
    return await _run_tool("curl", ctx.deps, **kwargs)


@cannon_agent.tool
async def python_exec(
    ctx: RunContext[CannonDeps],
    code: str,
    timeout: int = 60,
) -> str:
    """Execute a Python script for custom logic, parsing, payloads, complex requests."""
    return await _run_tool("python_exec", ctx.deps, code=code, timeout=timeout)


@cannon_agent.tool
async def vuln_lookup(
    ctx: RunContext[CannonDeps],
    query: str,
    subtopic: str | None = None,
) -> str:
    """Search the vulnerability knowledge base for payloads and exploitation techniques."""
    kwargs: dict[str, Any] = {"query": query}
    if subtopic:
        kwargs["subtopic"] = subtopic
    return await _run_tool("vuln_lookup", ctx.deps, **kwargs)


@cannon_agent.tool
async def interactsh(
    ctx: RunContext[CannonDeps],
    action: str,
    url: str | None = None,
    timeout: int = 10,
    poll_interval: int = 5,
) -> str:
    """Out-of-band interaction server for blind vulnerability detection.

    Args:
        action: 'start' to get a callback URL, 'poll' to check for interactions, 'stop' to end.
        url: The interactsh callback URL (required for 'poll' and 'stop').
        timeout: Seconds to wait when polling (default: 10).
        poll_interval: Interval between server polls in seconds (default: 5, for 'start').
    """
    kwargs: dict[str, Any] = {"action": action, "timeout": timeout, "poll_interval": poll_interval}
    if url:
        kwargs["url"] = url
    return await _run_tool("interactsh", ctx.deps, **kwargs)


@cannon_agent.tool
async def arjun(
    ctx: RunContext[CannonDeps],
    url: str | None = None,
    list: str | None = None,
    method: str = "GET",
    headers: list[str] | None = None,
    wordlist: str | None = None,
    threads: int = 2,
) -> str:
    """Discover hidden HTTP parameters (GET, POST, JSON) on endpoints.

    Args:
        url: Target URL to discover parameters on.
        list: Path to file with URLs to test.
        method: HTTP method / param type: GET, POST, JSON, XML (default: GET).
        headers: HTTP headers as 'Key: Value' strings.
        wordlist: Custom wordlist for parameter names.
        threads: Concurrent threads (default: 2).
    """
    kwargs: dict[str, Any] = {"method": method, "threads": threads}
    if url:
        kwargs["url"] = url
    if list:
        kwargs["list"] = list
    if headers:
        kwargs["headers"] = headers
    if wordlist:
        kwargs["wordlist"] = wordlist
    return await _run_tool("arjun", ctx.deps, **kwargs)


@cannon_agent.tool
async def sqlmap(
    ctx: RunContext[CannonDeps],
    url: str | None = None,
    request_file: str | None = None,
    data: str | None = None,
    param: str | None = None,
    cookie: str | None = None,
    headers: list[str] | None = None,
    technique: str | None = None,
    level: int = 1,
    risk: int = 1,
    tamper: str | None = None,
    random_agent: bool = True,
    dbs: bool = False,
    tables: bool = False,
    current_db: bool = False,
    current_user: bool = False,
    threads: int = 1,
    timeout: int = 30,
) -> str:
    """Automated SQL injection scanner with WAF bypass support.

    Args:
        url: Target URL with query params (e.g. 'https://example.com/page?id=1').
        request_file: Path to file with raw HTTP request (alternative to url).
        data: POST data string (e.g. 'username=admin&password=test').
        param: Specific parameter to test. Tests all by default.
        cookie: Cookie string for authenticated testing.
        headers: HTTP headers as 'Key: Value' strings.
        technique: SQLi techniques: B=boolean, E=error, U=union, S=stacked, T=time-blind.
        level: Testing depth 1-5 (default: 1).
        risk: Payload aggressiveness 1-3 (default: 1).
        tamper: WAF bypass tamper scripts (e.g. 'space2comment,between,randomcase').
        random_agent: Use random User-Agent (default: true).
        dbs: Enumerate databases after finding injection.
        tables: Enumerate tables after finding injection.
        current_db: Get current database name.
        current_user: Get current database user.
        threads: Max concurrent requests (default: 1).
        timeout: Per-request timeout in seconds (default: 30).
    """
    kwargs: dict[str, Any] = {
        "level": level, "risk": risk,
        "random_agent": random_agent, "threads": threads, "timeout": timeout,
    }
    if url:
        kwargs["url"] = url
    if request_file:
        kwargs["request_file"] = request_file
    if data:
        kwargs["data"] = data
    if param:
        kwargs["param"] = param
    if cookie:
        kwargs["cookie"] = cookie
    if headers:
        kwargs["headers"] = headers
    if technique:
        kwargs["technique"] = technique
    if tamper:
        kwargs["tamper"] = tamper
    if dbs:
        kwargs["dbs"] = dbs
    if tables:
        kwargs["tables"] = tables
    if current_db:
        kwargs["current_db"] = current_db
    if current_user:
        kwargs["current_user"] = current_user
    return await _run_tool("sqlmap", ctx.deps, **kwargs)


@cannon_agent.tool
async def dalfox(
    ctx: RunContext[CannonDeps],
    url: str | None = None,
    mode: str = "url",
    list: str | None = None,
    param: str | None = None,
    data: str | None = None,
    cookie: str | None = None,
    headers: list[str] | None = None,
    blind: str | None = None,
    waf_evasion: bool = False,
    mining_dict: bool = False,
    mining_dom: bool = False,
    custom_payload: str | None = None,
    workers: int = 1,
    timeout: int = 10,
) -> str:
    """Automated XSS scanner with WAF bypass and blind XSS support.

    Args:
        url: Target URL with params to test (e.g. 'https://example.com/search?q=test').
        mode: 'url' for single URL, 'file' for URL list (default: url).
        list: Path to file with URLs (when mode='file').
        param: Specific parameter to test. Tests all by default.
        data: POST data for POST-based XSS testing.
        cookie: Cookie string for authenticated testing.
        headers: HTTP headers as 'Key: Value' strings.
        blind: Blind XSS callback URL (e.g. your interactsh URL).
        waf_evasion: Enable WAF evasion techniques.
        mining_dict: Enable dictionary-based parameter mining.
        mining_dom: Enable DOM-based XSS sink mining.
        custom_payload: Custom XSS payload to test.
        workers: Concurrent workers (default: 1).
        timeout: Per-request timeout in seconds (default: 10).
    """
    kwargs: dict[str, Any] = {
        "mode": mode, "waf_evasion": waf_evasion,
        "mining_dict": mining_dict, "mining_dom": mining_dom,
        "workers": workers, "timeout": timeout,
    }
    if url:
        kwargs["url"] = url
    if list:
        kwargs["list"] = list
    if param:
        kwargs["param"] = param
    if data:
        kwargs["data"] = data
    if cookie:
        kwargs["cookie"] = cookie
    if headers:
        kwargs["headers"] = headers
    if blind:
        kwargs["blind"] = blind
    if custom_payload:
        kwargs["custom_payload"] = custom_payload
    return await _run_tool("dalfox", ctx.deps, **kwargs)


@cannon_agent.tool
async def report_finding(
    ctx: RunContext[CannonDeps],
    title: str,
    severity: str,
    url: str,
    description: str,
    proof: str,
    impact: str = "",
    remediation: str = "",
) -> str:
    """Report a confirmed vulnerability finding. Call immediately when you confirm a bug.

    Args:
        title: Short name (e.g. "Reflected XSS in search parameter")
        severity: One of: critical, high, medium, low, info
        url: The vulnerable URL/endpoint
        description: What the vulnerability is
        proof: The payload, request/response, or output that confirms it
        impact: What an attacker can achieve
        remediation: How to fix it
    """
    log.info(
        "[cannon.fail][%s] Finding: %s[/] at %s",
        severity.upper(), title, url,
    )
    ctx.deps.tracker.record_finding(
        title=title, severity=severity, url=url,
        description=description, proof=proof,
        impact=impact, remediation=remediation,
        iteration=ctx.deps.iteration,
    )
    ctx.deps.tracker.save(settings.output_dir)
    ctx.deps.findings.append({
        "tool": "report_finding",
        "args": {"title": title, "severity": severity, "url": url},
        "success": True, "output_lines": 0,
    })
    return f"Finding recorded: [{severity.upper()}] {title} at {url}"


@cannon_agent.tool
async def spawn_agent(
    ctx: RunContext[CannonDeps],
    target: str,
    prompt: str | None = None,
) -> str:
    """Spawn a child agent to independently pentest a specific target (subdomain/URL).

    Args:
        target: The target URL or subdomain for the child agent.
        prompt: Optional instructions. If not provided, does a full web app assessment.
    """
    if ctx.deps.is_child:
        return "Error: child agents cannot spawn more agents."

    # Normalize target
    if not target.startswith("http"):
        target = f"https://{target}"

    if not prompt:
        prompt = (
            f"Perform a full web application security assessment on {target}. "
            f"This is a subdomain discovered during recon of {ctx.deps.target}. "
            f"Focus on this specific host. Be thorough."
        )

    log.info(
        "[cannon.phase]Spawning child agent[/] for [cannon.target]%s[/]",
        target,
    )

    task = asyncio.create_task(
        _spawn_child(ctx.deps, target, prompt),
        name=f"child:{target}",
    )
    ctx.deps._child_tasks.append(task)

    ctx.deps.tracker.record_tool_call(
        tool_name="spawn_agent",
        args={"target": target},
        stdout=f"Child agent spawned for {target}",
        stderr="", success=True, iteration=ctx.deps.iteration,
    )
    ctx.deps.tracker.save(settings.output_dir)

    return (
        f"Child agent spawned for {target}. "
        f"It runs independently in the background. "
        f"Currently {len(ctx.deps._child_tasks)} child agent(s) running."
    )


# ── Child agent spawning ──────────────────────────────────────────────

async def _spawn_child(parent_deps: CannonDeps, target: str, prompt: str) -> dict[str, Any]:
    """Run a child agent under the shared semaphore."""
    sem = parent_deps.get_semaphore()
    async with sem:
        child_log = get_logger(f"child.{target[:40]}")
        child_log.info("[cannon.phase]Child agent starting[/] for [cannon.target]%s[/]", target)

        try:
            report, tracker = await run_agent(
                target=target,
                scope=parent_deps.scope,
                prompt=prompt,
                concurrency=parent_deps.concurrency,
                is_child=True,
                parent_deps=parent_deps,
            )
            findings_count = sum(1 for n in tracker._nodes if n.type == "finding")
            child_log.info(
                "[cannon.success]Child agent done[/] for %s — %d findings",
                target, findings_count,
            )
            return {
                "target": target, "status": "completed",
                "findings": findings_count,
                "report_summary": report[:500] if report else "",
            }
        except Exception as e:
            child_log.error("[cannon.fail]Child agent crashed[/] for %s: %s", target, e)
            return {
                "target": target, "status": "error",
                "findings": 0, "error": str(e),
            }


async def _wait_for_children(deps: CannonDeps) -> str:
    """Wait for all child agents and return a summary."""
    if not deps._child_tasks:
        return ""

    log.info("[cannon.phase]Waiting for %d child agent(s)[/]", len(deps._child_tasks))

    results = await asyncio.gather(*deps._child_tasks, return_exceptions=True)
    parts = []
    for r in results:
        if isinstance(r, Exception):
            parts.append(f"- Child agent error: {r}")
        elif isinstance(r, dict):
            parts.append(
                f"- {r.get('target', '?')}: {r.get('status', 'unknown')}, "
                f"{r.get('findings', 0)} finding(s)"
            )
    deps._child_tasks.clear()
    return "\n".join(parts)


# ── Main run function ─────────────────────────────────────────────────

async def run_agent(
    target: str,
    scope: str | None = None,
    prompt: str | None = None,
    concurrency: int = 5,
    is_child: bool = False,
    parent_deps: CannonDeps | None = None,
) -> tuple[str, AttackTracker]:
    """Run the cannon agent. Returns (report, tracker)."""
    scope = scope or target
    run_id = _make_run_id(target)

    tracker = AttackTracker(
        run_id=run_id, target=target,
        scope=scope, prompt=prompt or "",
    )

    deps = CannonDeps(
        target=target, scope=scope,
        tracker=tracker, run_id=run_id,
        is_child=is_child, concurrency=concurrency,
        _parent_deps=parent_deps,
    )

    model = get_model(settings.model)

    user_prompt = prompt or (
        "Start the bug bounty assessment. Begin with recon, "
        "then work through discovery and vulnerability hunting."
    )

    label = "Child Agent" if is_child else "Cannon"
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n[bold]Scope:[/bold] {scope}",
        title=f"[bold red]{label}[/bold red] - Web Pentest Agent",
        border_style="red",
    ))

    available = registry.available()
    all_tools = registry.all()
    log.info("Tools: %d/%d installed", len(available), len(all_tools))

    try:
        async with cannon_agent.iter(
            user_prompt,
            deps=deps,
            model=model,
            usage_limits=UsageLimits(request_limit=settings.max_iterations),
        ) as agent_run:
            async for node in agent_run:
                if Agent.is_model_request_node(node):
                    deps.iteration += 1
                    log.info("[cannon.phase]--- Iteration %d ---[/]", deps.iteration)
                    console.rule(f"[bold]Iteration {deps.iteration}[/bold]")

                elif Agent.is_call_tools_node(node):
                    # Print reasoning from the model response
                    if hasattr(node, "model_response"):
                        for part in node.model_response.parts:
                            if hasattr(part, "content") and not hasattr(part, "tool_name"):
                                text = part.content
                                if text and text.strip():
                                    console.print()
                                    console.print(Markdown(text))
                                    console.print()
                                    tracker.record_reasoning(text, deps.iteration)
                                    tracker.save(settings.output_dir)

                        # Log tool names
                        tool_names = [
                            p.tool_name for p in node.model_response.parts
                            if hasattr(p, "tool_name")
                        ]
                        if tool_names:
                            log.info("Calling tools: %s", ", ".join(tool_names))

        # Get the final report
        report = agent_run.result.output if agent_run.result else "Assessment complete (no report generated)."

        # Wait for child agents
        if deps._child_tasks:
            children_summary = await _wait_for_children(deps)
            if children_summary:
                report += f"\n\n## Child Agent Results\n{children_summary}"

        log.info(
            "[cannon.success]Assessment complete[/] after %d iterations, %d tool calls",
            deps.iteration, len(deps.findings),
        )

        console.print()
        console.print(Panel(
            Markdown(report),
            title="[bold green]Assessment Complete[/bold green]",
            border_style="green",
        ))

        tracker.finish("completed")
        path = tracker.save(settings.output_dir)
        log.info("Attack graph saved to %s", path)

        return report, tracker

    except Exception:
        for task in deps._child_tasks:
            task.cancel()
        tracker.finish("error")
        tracker.save(settings.output_dir)
        raise
