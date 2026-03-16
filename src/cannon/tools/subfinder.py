"""Subfinder - passive subdomain enumeration tool."""

from typing import Any

from cannon.tools.base import Tool, registry


class SubfinderTool(Tool):
    name = "subfinder"
    description = "Passive subdomain enumeration. Discovers subdomains of a target domain using passive sources."
    binary = "subfinder"

    def build_args(self, **kwargs: Any) -> list[str]:
        args = ["-d", kwargs["domain"], "-silent"]
        if kwargs.get("recursive"):
            args.append("-recursive")
        if kwargs.get("sources"):
            args.extend(["-sources", kwargs["sources"]])
        return args

    def openai_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain to enumerate subdomains for (e.g. example.com)",
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Enable recursive subdomain enumeration",
                        "default": False,
                    },
                    "sources": {
                        "type": "string",
                        "description": "Comma-separated list of sources to use (e.g. 'crtsh,virustotal')",
                    },
                },
                "required": ["domain"],
            },
        }


registry.register(SubfinderTool())
