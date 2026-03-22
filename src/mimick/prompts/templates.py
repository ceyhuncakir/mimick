from __future__ import annotations

from pathlib import Path

_PROMPTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "prompts"


def _load(name: str) -> str:
    return (_PROMPTS_DIR / name).read_text(encoding="utf-8")


def recon_plan() -> str:
    return _load("recon_plan.md")


def discovery_plan(host_count: int, technologies: str) -> str:
    return (
        _load("discovery_plan.md")
        .replace("{host_count}", str(host_count))
        .replace("{technologies}", technologies)
    )


def vuln_scan_plan(targets: str, technologies: str) -> str:
    return (
        _load("vuln_scan_plan.md")
        .replace("{targets}", targets)
        .replace("{technologies}", technologies)
    )
