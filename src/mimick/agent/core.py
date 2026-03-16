"""Core agent built on PydanticAI for orchestrating pentesting tools."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic_ai import Agent, RunContext, UsageLimits
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from mimick.config import settings
from mimick.llm.client import get_model
from mimick.logger import get_logger
from mimick.prompts.system import build_system_prompt, format_tool_descriptions
from mimick.tools import registry
from mimick.tracker import AttackTracker
from mimick.validation.validator import validate_findings

console = Console()
log = get_logger("agent")


# ── Dependencies ──────────────────────────────────────────────────────

_TOOL_ATTACK_TYPE: dict[str, str] = {
    "sqlmap": "sqli",
    "dalfox": "xss",
    "nuclei": "vuln_scan",
    "ffuf": "fuzzing",
    "arjun": "param_discovery",
    "nmap": "port_scan",
    "interactsh": "oob",
}

_UNPRODUCTIVE_THRESHOLD = 5  # iterations with no new discoveries before hinting


@dataclass
class MimickDeps:
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
    _parent_deps: MimickDeps | None = field(default=None, repr=False)

    # Layer 5: Shared discovery bus — children push findings here
    _shared_child_findings: list[dict[str, Any]] = field(
        default_factory=list, repr=False
    )

    # Layer 6: Failure tracking — maps attack_type -> list of target URLs that failed
    _attack_failures: dict[str, list[str]] = field(default_factory=dict, repr=False)

    # Layer 6: Productivity tracking — detect stale iterations
    _unproductive_streak: int = field(default=0, repr=False)
    _last_node_count: int = field(default=1, repr=False)  # 1 = root target node

    def get_semaphore(self) -> asyncio.Semaphore:
        """Get or create the shared semaphore (root agent owns it)."""
        if self._parent_deps:
            return self._parent_deps.get_semaphore()
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)
        return self._semaphore

    def record_attack_failure(self, tool_name: str, target_url: str) -> None:
        """Record a failed attack attempt for a tool/attack type."""
        attack_type = _TOOL_ATTACK_TYPE.get(tool_name)
        if not attack_type:
            return
        self._attack_failures.setdefault(attack_type, []).append(target_url)

    def get_failure_summary(self) -> dict[str, int]:
        """Return {attack_type: failure_count} for types with multiple failures."""
        return {k: len(v) for k, v in self._attack_failures.items() if len(v) >= 2}

    def update_productivity(self) -> None:
        """Update the unproductive streak based on tracker node count changes."""
        current = self.tracker.node_count()
        if current == self._last_node_count:
            self._unproductive_streak += 1
        else:
            self._unproductive_streak = 0
        self._last_node_count = current


# ── Helpers ───────────────────────────────────────────────────────────


def _make_run_id(target: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe = target.replace("://", "_").replace("/", "_").replace(".", "_")
    return f"mimick_{safe}_{ts}"


async def _run_tool(name: str, deps: MimickDeps, **kwargs: Any) -> str:
    """Look up a CLI tool by name, execute it, record in tracker, return summary."""
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
        # Track attack-type failures for adaptive strategy
        deps.record_attack_failure(
            name, kwargs.get("url") or kwargs.get("target") or ""
        )

    deps.findings.append(
        {
            "tool": name,
            "args": kwargs,
            "success": result.success,
            "output_lines": len(result.stdout.splitlines()),
        }
    )

    deps.tracker.record_tool_call(
        tool_name=name,
        args=kwargs,
        stdout=result.stdout,
        stderr=result.stderr,
        success=result.success,
        iteration=deps.iteration,
    )
    deps.tracker.save(settings.output_dir)

    return result.summary()


# ── Dynamic context (Layer 6) ────────────────────────────────────────


def _build_dynamic_context(deps: MimickDeps) -> str:
    """Build a dynamic context section from tracker state and run metadata.

    This is appended to the system prompt every iteration so the agent
    adapts its strategy based on what it has discovered and what has failed.
    """
    # Only inject after initial iterations have produced data
    if deps.iteration < 2:
        return ""

    sections: list[str] = []
    sections.append("# Live Assessment Context (auto-updated each iteration)")

    # ── Tech stack ────────────────────────────────────────────────
    tech = deps.tracker.get_tech_summary()
    if tech:
        lines = ["## Detected Tech Stack"]
        for host, techs in list(tech.items())[:10]:
            lines.append(f"- **{host}**: {', '.join(techs)}")
        sections.append("\n".join(lines))

    # ── WAF ───────────────────────────────────────────────────────
    wafs = deps.tracker.get_waf_info()
    if wafs:
        sections.append(
            f"## WAF Detected\n- {', '.join(wafs)}\n"
            "Adjust payloads accordingly. Use tamper scripts with sqlmap."
        )

    # ── Attack failures ───────────────────────────────────────────
    failures = deps.get_failure_summary()
    if failures:
        lines = ["## Attack Failures (adapt your strategy)"]
        advice = {
            "sqli": "Try higher sqlmap level/risk, tamper scripts, or different injection points.",
            "xss": "Try different encoding, event handlers, or DOM-based vectors.",
            "vuln_scan": "Focus on manual testing instead of template scans.",
            "fuzzing": "Try different wordlists or switch to manual endpoint discovery.",
            "param_discovery": "Use browser JS analysis or manual parameter guessing.",
            "oob": "Check if outbound connections are blocked; try DNS-only exfil.",
        }
        for attack_type, count in failures.items():
            hint = advice.get(attack_type, "Try a different approach.")
            lines.append(f"- **{attack_type}** failed {count} time(s). {hint}")
        sections.append("\n".join(lines))

    # ── Child agent findings (shared bus) ─────────────────────────
    child_findings = deps._shared_child_findings
    if child_findings:
        lines = ["## Child Agent Findings (already discovered — do NOT duplicate)"]
        for f in child_findings[:20]:
            lines.append(
                f"- [{f.get('severity', '?').upper()}] {f.get('title', '?')} "
                f"at {f.get('url', '?')}"
            )
        sections.append("\n".join(lines))

    # ── Discovered params (high-value targets) ────────────────────
    params = deps.tracker.get_discovered_params()
    if params:
        lines = ["## Discovered Parameters (test each for injection)"]
        for url, plist in list(params.items())[:10]:
            lines.append(f"- **{url}**: {', '.join(plist[:8])}")
        sections.append("\n".join(lines))

    # ── Endpoint coverage ─────────────────────────────────────────
    endpoints = deps.tracker.get_discovered_endpoints()
    findings = deps.tracker.get_findings_summary()
    if endpoints:
        sections.append(
            f"## Coverage\n"
            f"- {len(endpoints)} endpoint(s) discovered\n"
            f"- {len(findings)} finding(s) reported so far"
        )

    # ── Early termination hint ────────────────────────────────────
    if deps._unproductive_streak >= _UNPRODUCTIVE_THRESHOLD:
        sections.append(
            "## ⚠ Stale Assessment\n"
            f"The last {deps._unproductive_streak} iterations discovered nothing new. "
            "Consider:\n"
            "1. Are there untested endpoints or parameters? If yes, test them.\n"
            "2. Have you tried all bypass techniques for confirmed injection points?\n"
            "3. If the attack surface is exhausted, write your final report and stop."
        )

    if len(sections) <= 1:
        return ""
    return "\n\n".join(sections)


# ── Build the PydanticAI agent ────────────────────────────────────────

mimick_agent = Agent[MimickDeps, str](
    deps_type=MimickDeps,
    output_type=str,
)


@mimick_agent.instructions
async def system_instructions(ctx: RunContext[MimickDeps]) -> str:
    """Build the full system prompt with tools, scope, and dynamic context."""
    deps = ctx.deps

    # Update productivity tracking each time the LLM gets new instructions
    if deps.iteration > 1:
        deps.update_productivity()

    tool_desc = format_tool_descriptions(registry.all(), is_child=deps.is_child)
    base = build_system_prompt(tool_desc, target=deps.target, scope=deps.scope)

    # Append dynamic context (tech stack, failures, child findings, coverage)
    dynamic = _build_dynamic_context(deps)
    if dynamic:
        return f"{base}\n\n{dynamic}"
    return base


# ── Tool registrations ────────────────────────────────────────────────
# Each wraps the existing CLI tool via _run_tool()


@mimick_agent.tool
async def subfinder(
    ctx: RunContext[MimickDeps],
    domain: str,
    recursive: bool = False,
    sources: str | None = None,
) -> str:
    """Passive subdomain enumeration. Discovers subdomains of a target domain."""
    kwargs: dict[str, Any] = {"domain": domain, "recursive": recursive}
    if sources:
        kwargs["sources"] = sources
    return await _run_tool("subfinder", ctx.deps, **kwargs)


@mimick_agent.tool
async def httpx(
    ctx: RunContext[MimickDeps],
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
        "status_code": status_code,
        "title": title,
        "tech_detect": tech_detect,
        "web_server": web_server,
        "follow_redirects": follow_redirects,
    }
    if target:
        kwargs["target"] = target
    if list:
        kwargs["list"] = list
    if ports:
        kwargs["ports"] = ports
    return await _run_tool("httpx", ctx.deps, **kwargs)


@mimick_agent.tool
async def nuclei(
    ctx: RunContext[MimickDeps],
    target: str | None = None,
    list: str | None = None,
    templates: str | None = None,
    tags: str | None = None,
    severity: str | None = None,
    rate_limit: int = 150,
    automatic_scan: bool = False,
) -> str:
    """Fast vulnerability scanner with YAML templates. Scans for CVEs, misconfigs, etc."""
    kwargs: dict[str, Any] = {
        "rate_limit": rate_limit,
        "automatic_scan": automatic_scan,
    }
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


@mimick_agent.tool
async def ffuf(
    ctx: RunContext[MimickDeps],
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
        "url": url,
        "wordlist": wordlist,
        "method": method,
        "threads": threads,
        "recursion": recursion,
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


@mimick_agent.tool
async def nmap(
    ctx: RunContext[MimickDeps],
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
        "target": target,
        "scan_type": scan_type,
        "service_detection": service_detection,
        "os_detection": os_detection,
        "timing": timing,
    }
    if ports:
        kwargs["ports"] = ports
    if top_ports is not None:
        kwargs["top_ports"] = top_ports
    if scripts:
        kwargs["scripts"] = scripts
    return await _run_tool("nmap", ctx.deps, **kwargs)


@mimick_agent.tool
async def katana(
    ctx: RunContext[MimickDeps],
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
        "depth": depth,
        "js_crawl": js_crawl,
        "headless": headless,
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


@mimick_agent.tool
async def wafw00f(
    ctx: RunContext[MimickDeps],
    target: str,
    scan_all: bool = False,
) -> str:
    """Detect Web Application Firewalls (WAFs) protecting a target."""
    return await _run_tool("wafw00f", ctx.deps, target=target, scan_all=scan_all)


@mimick_agent.tool
async def curl(
    ctx: RunContext[MimickDeps],
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
        "url": url,
        "method": method,
        "follow_redirects": follow_redirects,
        "insecure": insecure,
        "max_time": max_time,
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


@mimick_agent.tool
async def python_exec(
    ctx: RunContext[MimickDeps],
    code: str,
    timeout: int = 60,
) -> str:
    """Execute a Python script for custom logic, parsing, payloads, complex requests."""
    return await _run_tool("python_exec", ctx.deps, code=code, timeout=timeout)


@mimick_agent.tool
async def vuln_lookup(
    ctx: RunContext[MimickDeps],
    query: str,
    subtopic: str | None = None,
) -> str:
    """Search the vulnerability knowledge base for payloads and exploitation techniques."""
    kwargs: dict[str, Any] = {"query": query}
    if subtopic:
        kwargs["subtopic"] = subtopic
    return await _run_tool("vuln_lookup", ctx.deps, **kwargs)


@mimick_agent.tool
async def interactsh(
    ctx: RunContext[MimickDeps],
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
    kwargs: dict[str, Any] = {
        "action": action,
        "timeout": timeout,
        "poll_interval": poll_interval,
    }
    if url:
        kwargs["url"] = url
    return await _run_tool("interactsh", ctx.deps, **kwargs)


@mimick_agent.tool
async def arjun(
    ctx: RunContext[MimickDeps],
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


@mimick_agent.tool
async def sqlmap(
    ctx: RunContext[MimickDeps],
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
        "level": level,
        "risk": risk,
        "random_agent": random_agent,
        "threads": threads,
        "timeout": timeout,
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


@mimick_agent.tool
async def dalfox(
    ctx: RunContext[MimickDeps],
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
        "mode": mode,
        "waf_evasion": waf_evasion,
        "mining_dict": mining_dict,
        "mining_dom": mining_dom,
        "workers": workers,
        "timeout": timeout,
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


@mimick_agent.tool
async def browser(
    ctx: RunContext[MimickDeps],
    url: str,
    action: str = "extract_info",
    js_code: str | None = None,
    wait_for: str | None = None,
    cookie: str | None = None,
    timeout: int = 15000,
) -> str:
    """Render a page in a headless browser (Playwright). Use for JS-heavy pages (SPAs, AngularJS, React, Vue).

    Args:
        url: The URL to render in the headless browser.
        action: 'extract_info' (default) returns rendered text, links, JS libs/versions, cookies, console output.
                'get_rendered_html' returns full rendered DOM HTML.
                'execute_js' runs custom JavaScript in page context (requires js_code).
                'screenshot' saves a full-page screenshot.
        js_code: JavaScript to execute (only for action='execute_js').
        wait_for: CSS selector to wait for before extracting (e.g. '#app', '.loaded').
        cookie: Cookie string for authenticated browsing ('name=value; name2=value2').
        timeout: Page load timeout in milliseconds (default: 15000).
    """
    kwargs: dict[str, Any] = {
        "url": url,
        "action": action,
        "timeout": timeout,
    }
    if js_code:
        kwargs["js_code"] = js_code
    if wait_for:
        kwargs["wait_for"] = wait_for
    if cookie:
        kwargs["cookie"] = cookie
    return await _run_tool("browser", ctx.deps, **kwargs)


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
    """Report a confirmed vulnerability finding. Call immediately when you confirm a bug.

    Args:
        title: Short name (e.g. "Reflected XSS in search parameter")
        severity: One of: critical, high, medium, low, info
        url: The vulnerable URL/endpoint
        description: What the vulnerability is
        proof: The payload, request/response, or output that confirms it
        reproduction: REQUIRED. Steps to reproduce and validate this finding.
            A list of step objects, each with:
            - method: HTTP method (GET, POST, PUT, DELETE)
            - url: the exact URL to request
            - headers: dict of HTTP headers (optional)
            - body: request body string (optional, for POST/PUT)
            - expect: dict describing what confirms the vuln:
                - status: expected HTTP status code (e.g. 200)
                - body_contains: string that must appear in response body
                - header_absent: header name that should be missing
                - header_contains: dict {header_name: expected_substring}

            Example for CORS:
            [{"method": "GET", "url": "http://target/", "headers": {"Origin": "https://attacker.com"},
              "expect": {"header_contains": {"access-control-allow-origin": "attacker.com"}}}]

            Example for SQLi:
            [{"method": "POST", "url": "http://target/api/login",
              "headers": {"Content-Type": "application/json"},
              "body": "{\"username\": \"admin' OR 1=1--\", \"password\": \"x\"}",
              "expect": {"status": 200, "body_contains": "success"}}]

            Example for missing header:
            [{"method": "GET", "url": "http://target/",
              "expect": {"header_absent": "content-security-policy"}}]
        impact: What an attacker can achieve
        remediation: How to fix it
    """
    # Dedup: check if this finding was already reported (by this agent or a child)
    if ctx.deps.tracker.is_duplicate_finding(url, title):
        log.info("Duplicate finding skipped: %s at %s", title, url)
        return f"Duplicate finding (already reported): [{severity.upper()}] {title} at {url}"

    # Also check against child findings on the shared bus
    for cf in ctx.deps._shared_child_findings:
        if (
            cf.get("url", "").rstrip("/").lower() == url.rstrip("/").lower()
            and cf.get("title", "").lower().strip() == title.lower().strip()
        ):
            log.info("Duplicate finding (child already found): %s at %s", title, url)
            return f"Duplicate finding (child agent already reported): [{severity.upper()}] {title} at {url}"

    log.info(
        "[mimick.fail][%s] Finding: %s[/] at %s",
        severity.upper(),
        title,
        url,
    )
    ctx.deps.tracker.record_finding(
        title=title,
        severity=severity,
        url=url,
        description=description,
        proof=proof,
        reproduction=reproduction or [],
        impact=impact,
        remediation=remediation,
        iteration=ctx.deps.iteration,
    )
    ctx.deps.tracker.save(settings.output_dir)
    ctx.deps.findings.append(
        {
            "tool": "report_finding",
            "args": {"title": title, "severity": severity, "url": url},
            "success": True,
            "output_lines": 0,
        }
    )
    return f"Finding recorded: [{severity.upper()}] {title} at {url}"


def _build_child_brief(parent_deps: MimickDeps, child_target: str) -> str:
    """Build a focused brief for a child agent based on parent's recon data."""
    from urllib.parse import urlparse

    parts = [
        f"Perform a full web application security assessment on {child_target}.",
        f"This is a subdomain discovered during recon of {parent_deps.target}.",
    ]

    domain = urlparse(child_target).netloc

    # Inject tech stack info if known
    tech = parent_deps.tracker.get_tech_summary()
    for host, techs in tech.items():
        if domain in host:
            parts.append(f"Detected tech stack: {', '.join(techs)}.")
            # Add tech-specific focus areas
            tech_lower = " ".join(techs).lower()
            focus: list[str] = []
            if any(t in tech_lower for t in ("php", "laravel", "wordpress", "apache")):
                focus.append("PHP-specific vulns (LFI, RCE, SQLi)")
            if any(t in tech_lower for t in ("node", "express", "next")):
                focus.append("prototype pollution, SSRF, NoSQL injection")
            if any(t in tech_lower for t in ("java", "spring", "tomcat")):
                focus.append("deserialization, SSTI, XXE")
            if any(t in tech_lower for t in ("python", "django", "flask")):
                focus.append("SSTI, command injection, path traversal")
            if any(t in tech_lower for t in ("angular", "react", "vue")):
                focus.append("DOM XSS, CSTI, client-side vulns")
            if focus:
                parts.append(f"Focus areas: {'; '.join(focus)}.")
            break

    # Inject WAF info
    wafs = parent_deps.tracker.get_waf_info()
    if wafs:
        parts.append(
            f"WAF detected: {', '.join(wafs)}. "
            "Use tamper scripts, encoding, and WAF bypass techniques."
        )

    # Inject parent's existing findings to avoid duplication
    existing = parent_deps.tracker.get_findings_summary()
    child_findings = parent_deps._shared_child_findings
    all_known = existing + child_findings
    if all_known:
        known_urls = {f.get("url", "") for f in all_known if domain in f.get("url", "")}
        if known_urls:
            parts.append(
                f"Already-found vulnerable endpoints (do NOT re-test): "
                f"{', '.join(list(known_urls)[:5])}."
            )

    parts.append("Be thorough.")
    return " ".join(parts)


@mimick_agent.tool
async def spawn_agent(
    ctx: RunContext[MimickDeps],
    target: str,
    prompt: str | None = None,
) -> str:
    """Spawn a child agent to independently pentest a specific target (subdomain/URL).

    Args:
        target: The target URL or subdomain for the child agent.
        prompt: Optional instructions. If not provided, builds a focused brief from recon data.
    """
    if ctx.deps.is_child:
        return "Error: child agents cannot spawn more agents."

    # Normalize target
    if not target.startswith("http"):
        target = f"https://{target}"

    if not prompt:
        prompt = _build_child_brief(ctx.deps, target)

    log.info(
        "[mimick.phase]Spawning child agent[/] for [mimick.target]%s[/]",
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
        stderr="",
        success=True,
        iteration=ctx.deps.iteration,
    )
    ctx.deps.tracker.save(settings.output_dir)

    return (
        f"Child agent spawned for {target}. "
        f"It runs independently in the background. "
        f"Currently {len(ctx.deps._child_tasks)} child agent(s) running."
    )


# ── Child agent spawning ──────────────────────────────────────────────


async def _spawn_child(
    parent_deps: MimickDeps, target: str, prompt: str
) -> dict[str, Any]:
    """Run a child agent under the shared semaphore."""
    sem = parent_deps.get_semaphore()
    async with sem:
        child_log = get_logger(f"child.{target[:40]}")
        child_log.info(
            "[mimick.phase]Child agent starting[/] for [mimick.target]%s[/]", target
        )

        try:
            report, tracker = await run_agent(
                target=target,
                scope=parent_deps.scope,
                prompt=prompt,
                concurrency=parent_deps.concurrency,
                is_child=True,
                parent_deps=parent_deps,
            )

            # Push child findings to parent's shared bus so parent
            # and sibling children can see what was already found.
            child_findings = tracker.get_findings_summary()
            parent_deps._shared_child_findings.extend(child_findings)

            findings_count = len(child_findings)
            child_log.info(
                "[mimick.success]Child agent done[/] for %s — %d findings",
                target,
                findings_count,
            )
            return {
                "target": target,
                "status": "completed",
                "findings": findings_count,
                "report_summary": report[:500] if report else "",
            }
        except Exception as e:
            child_log.error("[mimick.fail]Child agent crashed[/] for %s: %s", target, e)
            return {
                "target": target,
                "status": "error",
                "findings": 0,
                "error": str(e),
            }


async def _wait_for_children(deps: MimickDeps) -> str:
    """Wait for all child agents and return a summary."""
    if not deps._child_tasks:
        return ""

    log.info("[mimick.phase]Waiting for %d child agent(s)[/]", len(deps._child_tasks))

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
    parent_deps: MimickDeps | None = None,
) -> tuple[str, AttackTracker]:
    """Run the mimick agent. Returns (report, tracker)."""
    scope = scope or target
    run_id = _make_run_id(target)

    tracker = AttackTracker(
        run_id=run_id,
        target=target,
        scope=scope,
        prompt=prompt or "",
    )

    deps = MimickDeps(
        target=target,
        scope=scope,
        tracker=tracker,
        run_id=run_id,
        is_child=is_child,
        concurrency=concurrency,
        _parent_deps=parent_deps,
    )

    model = get_model(settings.model)

    user_prompt = prompt or (
        "Start the bug bounty assessment. Begin with recon, "
        "then work through discovery and vulnerability hunting."
    )

    label = "Child Agent" if is_child else "Mimick"
    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n[bold]Scope:[/bold] {scope}",
            title=f"[bold red]{label}[/bold red] - Web Pentest Agent",
            border_style="red",
        )
    )

    available = registry.available()
    all_tools = registry.all()
    log.info("Tools: %d/%d installed", len(available), len(all_tools))

    try:
        async with mimick_agent.iter(
            user_prompt,
            deps=deps,
            model=model,
            usage_limits=UsageLimits(request_limit=settings.max_iterations),
        ) as agent_run:
            async for node in agent_run:
                if Agent.is_model_request_node(node):
                    deps.iteration += 1
                    log.info("[mimick.phase]--- Iteration %d ---[/]", deps.iteration)
                    console.rule(f"[bold]Iteration {deps.iteration}[/bold]")

                    # Early termination: if the agent has been unproductive
                    # for 2x the threshold, force stop
                    if deps._unproductive_streak >= _UNPRODUCTIVE_THRESHOLD * 2:
                        log.info(
                            "[mimick.phase]Early termination[/]: %d unproductive iterations",
                            deps._unproductive_streak,
                        )
                        break

                elif Agent.is_call_tools_node(node):
                    # Print reasoning from the model response
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

                        # Log tool names
                        tool_names = [
                            p.tool_name
                            for p in node.model_response.parts
                            if hasattr(p, "tool_name")
                        ]
                        if tool_names:
                            log.info("Calling tools: %s", ", ".join(tool_names))

        # Get the final report
        report = (
            agent_run.result.output
            if agent_run.result
            else "Assessment complete (no report generated)."
        )

        # Wait for child agents
        if deps._child_tasks:
            children_summary = await _wait_for_children(deps)
            if children_summary:
                report += f"\n\n## Child Agent Results\n{children_summary}"

        log.info(
            "[mimick.success]Assessment complete[/] after %d iterations, %d tool calls",
            deps.iteration,
            len(deps.findings),
        )

        # ── Validation phase ──────────────────────────────────────────
        if not is_child:
            console.rule("[bold yellow]Validation Phase[/bold yellow]")
            validation_results = await validate_findings(tracker)

            if validation_results:
                report += _format_validation_section(validation_results)

                # Generate standalone validation script
                script_path = _write_validation_script(
                    tracker,
                    validation_results,
                    settings.output_dir,
                    run_id,
                )
                log.info("Validation script saved to %s", script_path)

            tracker.save(settings.output_dir)

        console.print()
        console.print(
            Panel(
                Markdown(report),
                title="[bold green]Assessment Complete[/bold green]",
                border_style="green",
            )
        )

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


# ── Validation helpers ────────────────────────────────────────────────


def _format_validation_section(results: list[dict[str, str]]) -> str:
    """Append a Validation Results section to the markdown report."""
    lines = ["\n\n## Validation Results\n"]
    lines.append("| # | Severity | Finding | Status | Detail |")
    lines.append("|---|----------|---------|--------|--------|")
    for i, r in enumerate(results, 1):
        icon = {"CONFIRMED": "✅", "UNCONFIRMED": "⚠️", "ERROR": "❌"}.get(
            r["status"], "?"
        )
        sev = r["severity"].upper() if r["severity"] else "—"
        detail = r["detail"][:80].replace("|", "\\|")
        title = r["title"][:50].replace("|", "\\|")
        lines.append(f"| {i} | {sev} | {title} | {icon} {r['status']} | {detail} |")

    c = sum(1 for r in results if r["status"] == "CONFIRMED")
    lines.append(f"\n**{c}/{len(results)}** findings independently confirmed.\n")
    return "\n".join(lines)


def _write_validation_script(
    tracker: AttackTracker,
    results: list[dict[str, str]],
    output_dir: Path,
    run_id: str,
) -> Path:
    """Generate a self-contained script that replays reproduction steps."""
    findings_data = []
    for node in tracker._nodes:
        if node.type != "finding":
            continue
        findings_data.append(
            {
                "id": node.id,
                "title": node.label,
                "severity": node.data.get("severity", ""),
                "url": node.data.get("url", ""),
                "reproduction": node.data.get("reproduction", []),
            }
        )

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
from urllib.error import URLError
from urllib.request import Request, urlopen

TIMEOUT = 12

FINDINGS = json.loads("""
{findings_json}
""")

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

RED, GREEN, YELLOW, BOLD, RESET = "\\033[91m", "\\033[92m", "\\033[93m", "\\033[1m", "\\033[0m"


def http(url, method="GET", headers=None, body=None):
    data = body.encode() if body else None
    req = Request(url, method=method, data=data)
    for k, v in (headers or {{}}).items():
        req.add_header(k, v)
    try:
        resp = urlopen(req, timeout=TIMEOUT, context=_CTX)
        rbody = resp.read().decode(errors="replace")
        rhdrs = {{k.lower(): v for k, v in resp.getheaders()}}
        return resp.status, rhdrs, rbody
    except URLError as e:
        if hasattr(e, "code"):
            rbody = e.read().decode(errors="replace") if hasattr(e, "read") else ""
            rhdrs = {{k.lower(): v for k, v in e.headers.items()}} if hasattr(e, "headers") else {{}}
            return e.code, rhdrs, rbody
        raise


def extract_cookies(resp_hdrs):
    \"\"\"Parse Set-Cookie headers into a name->value dict.\"\"\"
    cookies = {{}}
    raw = resp_hdrs.get("set-cookie", "")
    if not raw:
        return cookies
    parts = re.split(r",\\s*(?=[A-Za-z_][A-Za-z0-9_]*=)", raw)
    for part in parts:
        nv = part.split(";")[0].strip()
        if "=" in nv:
            name, _, value = nv.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


_PLACEHOLDER_RE = re.compile(r"REPLACE[_A-Z]*", re.IGNORECASE)


def inject_cookies(headers, session_cookies):
    \"\"\"Inject session cookies — replaces placeholder values or adds Cookie header.\"\"\"
    if not session_cookies:
        return
    cookie_key = None
    for k in headers:
        if k.lower() == "cookie":
            cookie_key = k
            break
    cookie_val = "; ".join(f"{{k}}={{v}}" for k, v in session_cookies.items())
    if cookie_key is None:
        headers["Cookie"] = cookie_val
    elif _PLACEHOLDER_RE.search(headers[cookie_key]):
        headers[cookie_key] = cookie_val


def check_expect(expect, status, headers, body):
    passed, failed = [], []
    if "status" in expect:
        (passed if status == expect["status"] else failed).append(
            f"status {{status}} (want {{expect['status']}})")
    if "body_contains" in expect:
        n = expect["body_contains"]
        (passed if n in body else failed).append(f"body {{'contains' if n in body else 'missing'}} '{{n[:40]}}'")
    if "body_not_contains" in expect:
        n = expect["body_not_contains"]
        (passed if n not in body else failed).append(f"body '{{n[:40]}}' {{'absent' if n not in body else 'present'}}")
    if "header_absent" in expect:
        h = expect["header_absent"].lower()
        (passed if h not in headers else failed).append(f"header '{{h}}' {{'absent' if h not in headers else 'present'}}")
    if "header_present" in expect:
        h = expect["header_present"].lower()
        (passed if h in headers else failed).append(f"header '{{h}}' {{'present' if h in headers else 'absent'}}")
    if "header_contains" in expect:
        for hname, want in expect["header_contains"].items():
            actual = headers.get(hname.lower(), "")
            (passed if want.lower() in actual.lower() else failed).append(
                f"{{hname}}={{'ok' if want.lower() in actual.lower() else repr(actual[:40])}}")
    if "status_not" in expect:
        u = expect["status_not"]
        (passed if status != u else failed).append(f"status {{status}} (not {{u}})")
    if "min_body_length" in expect:
        ml = expect["min_body_length"]
        (passed if len(body) >= ml else failed).append(f"body {{len(body)}}B (min {{ml}})")
    if failed:
        return False, "; ".join(failed)
    return True, "; ".join(passed) if passed else "ok"


def validate(finding):
    \"\"\"Replay reproduction steps with session cookie propagation.

    Only the LAST step determines CONFIRMED/UNCONFIRMED — earlier steps
    are setup (register/login) and their failures are tolerated.
    \"\"\"
    steps = finding.get("reproduction") or []
    if not steps:
        return "SKIPPED", "no reproduction steps"
    details = []
    last_passed = False
    session_cookies = {{}}
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
