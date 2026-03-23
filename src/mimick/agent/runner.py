from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from pydantic_ai import Agent, UsageLimits
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from mimick.agent.core import mimick_agent
from mimick.agent.deps import MimickDeps, UNPRODUCTIVE_THRESHOLD
from mimick.agent.validation import (
    format_validation_section,
    sync_validation_to_experiences,
    write_validation_script,
)
from mimick.config import settings
from mimick.llm.client import get_cache_settings, get_model
from mimick.logger import get_logger
from mimick.memory.store import ExperienceStore
from mimick.planner import AttackPlanner
from mimick.tracker import AttackTracker
from mimick.validation.validator import validate_findings

console = Console()
log = get_logger("agent.runner")

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


def _make_run_id(target: str) -> str:
    """Generate a unique run identifier from the target and current time.

    Args:
        target: The target URL.

    Returns:
        A filesystem-safe run ID string.
    """
    ts: str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe: str = target.replace("://", "_").replace("/", "_").replace(".", "_")
    return f"mimick_{safe}_{ts}"


async def spawn_child(
    parent_deps: MimickDeps, target: str, prompt: str
) -> dict[str, Any]:
    """Run a child agent under the parent's concurrency semaphore.

    Args:
        parent_deps: The parent agent's dependencies.
        target: URL for the child to assess.
        prompt: Initial prompt for the child agent.

    Returns:
        Dict with ``target``, ``status``, and ``findings`` count.
    """
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
            child_findings: list[dict[str, Any]] = tracker.get_findings_summary()
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
    """Await all child agent tasks and summarize their results.

    Args:
        deps: The parent agent's dependencies.

    Returns:
        Summary string of child results, or empty string if none.
    """
    if not deps._child_tasks:
        return ""

    log.info("[mimick.phase]Waiting for %d child agent(s)[/]", len(deps._child_tasks))
    results = await asyncio.gather(*deps._child_tasks, return_exceptions=True)
    parts: list[str] = [
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
    """Run the mimick pentesting agent.

    Args:
        target: The URL to assess.
        scope: Scope constraint (defaults to *target*).
        prompt: Optional custom initial prompt.
        concurrency: Maximum concurrent child agents.
        is_child: Whether this is a child agent invocation.
        parent_deps: Parent dependencies when running as a child.
        max_iterations: Override for the maximum iteration count.

    Returns:
        Tuple of the final report string and the attack tracker.
    """
    import mimick.agent.tools  # noqa: F401 — registers tools on mimick_agent

    scope = scope or target
    run_id: str = _make_run_id(target)
    max_iters: int = max_iterations or settings.max_iterations

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
    user_prompt: str = (
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
    from mimick.tools import registry

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

                        tool_names: list[str] = [
                            p.tool_name
                            for p in node.model_response.parts
                            if hasattr(p, "tool_name")
                        ]
                        if tool_names:
                            log.info("Calling tools: %s", ", ".join(tool_names))

        report: str = (
            agent_run.result.output
            if agent_run.result
            else "Assessment complete (no report generated)."
        )

        if deps._child_tasks:
            children_summary: str = await _wait_for_children(deps)
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
                report += format_validation_section(validation_results)
                script_path = write_validation_script(
                    tracker, validation_results, settings.output_dir, run_id
                )
                log.info("Validation script saved to %s", script_path)

                store: ExperienceStore | None = _get_experience_store()
                if store:
                    sync_validation_to_experiences(store, validation_results)

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
