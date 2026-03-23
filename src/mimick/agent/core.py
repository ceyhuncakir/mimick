"""Agent definition, system instructions, and shared tool execution helpers."""

from __future__ import annotations

import asyncio
import json
import shlex
from typing import Any

from pydantic_ai import Agent, RunContext

from mimick.agent.context import build_dynamic_context
from mimick.agent.deps import MimickDeps
from mimick.agent.strategy import (
    extract_from_command,
    extract_from_tool_call,
    extract_url_from_command,
)
from mimick.config import settings
from mimick.logger import get_logger
from mimick.prompts.system import build_system_prompt, format_tool_descriptions
from mimick.tools import registry
from mimick.tools.base import ToolResult

log = get_logger("agent")

mimick_agent = Agent[MimickDeps, str](deps_type=MimickDeps, output_type=str)


@mimick_agent.instructions
async def system_instructions(ctx: RunContext[MimickDeps]) -> str:
    """Build the full system prompt with tools, scope, and dynamic context."""
    deps: MimickDeps = ctx.deps
    if deps.iteration > 1:
        deps.update_productivity()

    tool_desc: str = format_tool_descriptions(registry.all(), is_child=deps.is_child)
    base: str = build_system_prompt(tool_desc, target=deps.target, scope=deps.scope)
    dynamic: str = build_dynamic_context(deps)
    return f"{base}\n\n{dynamic}" if dynamic else base


def record_and_track(
    deps: MimickDeps,
    tool_name: str,
    args: dict[str, Any],
    stdout: str,
    stderr: str,
    success: bool,
) -> None:
    """Record a tool invocation in both the findings list and the tracker.

    Args:
        deps: Current agent dependencies.
        tool_name: Name of the tool that was run.
        args: Arguments passed to the tool.
        stdout: Standard output from the tool.
        stderr: Standard error from the tool.
        success: Whether the tool completed successfully.
    """
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


async def run_tool(name: str, deps: MimickDeps, **kwargs: Any) -> str:
    """Execute a registered tool by name and record the result.

    Args:
        name: Tool registry key.
        deps: Current agent dependencies.
        **kwargs: Arguments forwarded to the tool.

    Returns:
        The tool's summary output string.
    """
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

    record_and_track(deps, name, kwargs, result.stdout, result.stderr, result.success)

    target_url: str = kwargs.get("url") or kwargs.get("target") or ""
    recon_tools = frozenset({"vuln_lookup", "wafw00f", "httpx", "subfinder"})
    if target_url and name not in recon_tools:
        strategy: str | None = extract_from_tool_call(name, kwargs)
        if strategy:
            deps.record_strategy(target_url, strategy)

    return result.summary()


async def run_command(command: str, deps: MimickDeps) -> str:
    """Execute a raw CLI command and record the result.

    Args:
        command: Shell command string.
        deps: Current agent dependencies.

    Returns:
        The command's summary output string.
    """
    parts: list[str] = shlex.split(command)
    tool_name: str = parts[0] if parts else "unknown"

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

    stdout: str = stdout_bytes.decode(errors="replace")
    stderr: str = stderr_bytes.decode(errors="replace")
    return_code: int = proc.returncode or 0
    success: bool = return_code == 0

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

    record_and_track(deps, tool_name, {"command": command}, stdout, stderr, success)

    strategy: str | None = extract_from_command(command)
    if strategy:
        target_url: str = extract_url_from_command(command)
        if target_url:
            deps.record_strategy(target_url, strategy)

    return ToolResult(
        tool_name=tool_name,
        command=command,
        stdout=stdout,
        stderr=stderr,
        return_code=return_code,
    ).summary()
