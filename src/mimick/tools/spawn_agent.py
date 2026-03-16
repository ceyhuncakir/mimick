"""spawn_agent - Launch a child agent to pentest a specific target."""

from __future__ import annotations

from typing import Any

from mimick.tools.base import Tool, ToolResult, registry


class SpawnAgent(Tool):
    """Spawn a parallel child agent to pentest a specific subdomain or host."""

    name = "spawn_agent"
    description = (
        "Spawn a child agent to independently pentest a specific target "
        "(subdomain or URL). The child agent runs its own full assessment "
        "in parallel. Use this after discovering subdomains to fan out testing. "
        "You can spawn multiple agents — they run concurrently up to the "
        "configured limit. Each child agent produces its own attack graph and report."
    )
    binary = ""

    def build_args(self, **kwargs: Any) -> list[str]:
        return []

    def is_available(self) -> bool:
        return True

    def openai_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target URL or subdomain for the child agent (e.g. 'https://api.example.com' or 'staging.example.com')",
                    },
                    "prompt": {
                        "type": "string",
                        "description": "Optional instructions for the child agent. If not provided, it will do a full web app assessment.",
                    },
                },
                "required": ["target"],
            },
        }

    async def run(self, **kwargs: Any) -> ToolResult:
        # Intercepted in agent/core.py — never actually runs
        return ToolResult(
            tool_name=self.name,
            command="spawn_agent",
            stdout="Agent spawned.",
            stderr="",
            return_code=0,
        )


registry.register(SpawnAgent())
