"""System prompt construction from Markdown templates."""

from __future__ import annotations

from pathlib import Path

_PROMPTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "prompts"


def _load(name: str) -> str:
    """Load a prompt template file by name from the prompts directory."""
    return (_PROMPTS_DIR / name).read_text(encoding="utf-8")


def build_system_prompt(
    tool_descriptions: str,
    target: str = "",
    scope: str = "",
) -> str:
    """Build the full system prompt with injected runtime values."""
    template = _load("system.md")
    reporting_rules = _load("reporting_rules.md")
    return (
        template.replace("{target}", target)
        .replace("{scope}", scope)
        .replace("{tool_descriptions}", tool_descriptions)
        .replace("{reporting_rules}", reporting_rules)
    )


def format_tool_descriptions(tools: list, is_child: bool = False) -> str:
    """Format installed CLI tool descriptions for the system prompt."""
    _INTERNAL_TOOLS = {"report_finding", "spawn_agent", "python_exec", "vuln_lookup"}

    return "\n".join(
        f"- **{tool.name}**: {tool.description}"
        for tool in tools
        if tool.name not in _INTERNAL_TOOLS
        and tool.is_available()
        and not (is_child and tool.name == "spawn_agent")
    )
