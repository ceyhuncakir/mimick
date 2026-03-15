"""CLI entrypoint for Cannon."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console

from cannon.config import settings
from cannon.logger import get_logger, setup_logging
from cannon.output.reporter import save_report

console = Console()
log = get_logger("cli")


@click.group()
@click.version_option(package_name="cannon")
def cli() -> None:
    """Cannon - AI-powered web penetration testing agent."""
    load_dotenv()


@cli.command()
@click.argument("target")
@click.option("--scope", "-s", default=None, help="Authorized scope (default: same as target)")
@click.option("--prompt", "-p", default=None, help="Custom prompt / task for the agent")
@click.option("--model", "-m", default=None, help="LLM model override (litellm format)")
@click.option("--max-iterations", "-i", type=int, default=None, help="Max agent iterations")
@click.option("--output-dir", "-o", default=None, type=click.Path(), help="Directory to save results (e.g. ./results/acme-corp)")
@click.option("--concurrency", "-c", default=5, type=int, help="Max parallel child agents when scanning subdomains (default: 5)")
@click.option("--no-save", is_flag=True, help="Don't save report to file")
@click.option("--log-level", "-l", default=None, help="Log level override (DEBUG, INFO, WARNING, ERROR)")
def scan(
    target: str,
    scope: str | None,
    prompt: str | None,
    model: str | None,
    max_iterations: int | None,
    output_dir: str | None,
    concurrency: int,
    no_save: bool,
    log_level: str | None,
) -> None:
    """Run a penetration test against TARGET.

    TARGET can be a domain (example.com) or URL (https://example.com).

    When the agent discovers subdomains, it can spawn parallel child agents
    to pentest each one. Use --concurrency to control how many run at once.

    Examples:

        cannon scan example.com

        cannon scan example.com -c 10

        cannon scan example.com -p "Focus only on SQL injection vectors"

        cannon scan https://app.example.com --scope "*.example.com"

        cannon scan example.com --model gpt-4o
    """
    level = log_level or settings.log_level

    if output_dir:
        settings.output_dir = Path(output_dir)

    # Set up file logging
    log_file = None
    if settings.log_file:
        settings.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
        log_file = settings.output_dir / f"cannon_{safe_target}_{timestamp}.log"

    setup_logging(level=level, log_file=log_file)

    if model:
        settings.model = model
    if max_iterations:
        settings.max_iterations = max_iterations

    log.info("Starting scan against [cannon.target]%s[/]", target)
    log.debug("Model: %s | Max iterations: %s | Concurrency: %d", settings.model, settings.max_iterations, concurrency)
    if log_file:
        log.info("Log file: %s", log_file)

    from cannon.agent.core import run_agent

    report, _tracker = asyncio.run(run_agent(
        target=target, scope=scope, prompt=prompt, concurrency=concurrency,
    ))

    if not no_save:
        path = save_report(target, report)
        log.info("Report saved to %s", path)
        console.print(f"\n[bold]Report saved to:[/bold] {path}")


@cli.command()
def tools() -> None:
    """List available security tools and their install status."""
    setup_logging(level=settings.log_level)

    from cannon.tools import registry

    console.print("\n[bold]Security Tools[/bold]\n")
    for tool in registry.all():
        if tool.is_available():
            console.print(f"  [green]✓[/green] [bold]{tool.name}[/bold] - {tool.description}")
        else:
            console.print(f"  [red]✗[/red] [bold]{tool.name}[/bold] - {tool.description} [dim](not installed)[/dim]")
    console.print()


@cli.command()
@click.option("--port", "-p", default=8117, type=int, help="Port to run on")
@click.option("--host", "-h", default="127.0.0.1", help="Host to bind to")
@click.option("--output-dir", "-o", default=None, type=click.Path(), help="Results directory to serve")
def web(port: int, host: str, output_dir: str | None) -> None:
    """Launch the attack vector map dashboard.

    Examples:

        cannon web

        cannon web --port 3000

        cannon web -o ./results/acme-corp
    """
    import uvicorn
    from cannon.web.app import create_app

    if output_dir:
        settings.output_dir = Path(output_dir)

    app = create_app(results_dir=settings.output_dir)

    console.print(f"\n[bold]Cannon[/bold] dashboard running at [link]http://{host}:{port}[/link]\n")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    cli()
