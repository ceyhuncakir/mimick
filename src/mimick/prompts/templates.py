"""Phase-specific prompt templates for reconnaissance, discovery, and scanning."""

from __future__ import annotations

from pathlib import Path

_PROMPTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "prompts"


def _load(name: str) -> str:
    """Load a prompt template file by name from the prompts directory."""
    return (_PROMPTS_DIR / name).read_text(encoding="utf-8")


def recon_plan() -> str:
    """Return the reconnaissance phase plan prompt."""
    return _load("recon_plan.md")


def discovery_plan(host_count: int, technologies: str) -> str:
    """Return the discovery phase plan prompt with injected context.

    Args:
        host_count: Number of discovered hosts.
        technologies: Comma-separated technology identifiers.

    Returns:
        Rendered discovery plan prompt string.
    """
    return (
        _load("discovery_plan.md")
        .replace("{host_count}", str(host_count))
        .replace("{technologies}", technologies)
    )


def vuln_scan_plan(targets: str, technologies: str) -> str:
    """Return the vulnerability scan plan prompt with injected context.

    Args:
        targets: Comma-separated target addresses.
        technologies: Comma-separated technology identifiers.

    Returns:
        Rendered vulnerability scan plan prompt string.
    """
    return (
        _load("vuln_scan_plan.md")
        .replace("{targets}", targets)
        .replace("{technologies}", technologies)
    )
