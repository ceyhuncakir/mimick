"""report_finding - Agent calls this to register a confirmed vulnerability."""

from __future__ import annotations

from typing import Any

from cannon.tools.base import Tool, ToolResult, registry


class ReportFinding(Tool):
    """Register a confirmed vulnerability finding in the attack graph."""

    name = "report_finding"
    description = (
        "Report a confirmed vulnerability finding. Call this every time you "
        "discover or confirm a vulnerability. The finding will be recorded in "
        "the attack graph with severity, URL, description, and proof."
    )
    binary = ""  # No binary needed

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
                    "title": {
                        "type": "string",
                        "description": "Short title of the vulnerability (e.g. 'Reflected XSS in search parameter')",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Severity level of the finding",
                    },
                    "url": {
                        "type": "string",
                        "description": "The vulnerable URL or endpoint",
                    },
                    "description": {
                        "type": "string",
                        "description": "What the vulnerability is and how it works",
                    },
                    "proof": {
                        "type": "string",
                        "description": "Proof of exploitation: the payload, request/response, or command output that confirms the vulnerability",
                    },
                    "impact": {
                        "type": "string",
                        "description": "What an attacker can achieve by exploiting this",
                    },
                    "remediation": {
                        "type": "string",
                        "description": "How to fix the vulnerability",
                    },
                },
                "required": ["title", "severity", "url", "description", "proof"],
            },
        }

    async def run(self, **kwargs: Any) -> ToolResult:
        # This tool is intercepted in agent/core.py — it never actually runs.
        # If it somehow gets here, return a success result.
        return ToolResult(
            tool_name=self.name,
            command="report_finding",
            stdout=f"Finding recorded: {kwargs.get('title', '')}",
            stderr="",
            return_code=0,
        )


registry.register(ReportFinding())
