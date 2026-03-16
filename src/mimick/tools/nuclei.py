"""Nuclei - fast vulnerability scanner using templates."""

from typing import Any

from mimick.tools.base import Tool, registry


class NucleiTool(Tool):
    name = "nuclei"
    description = (
        "Fast vulnerability scanner powered by YAML templates. "
        "Scans targets for known CVEs, misconfigurations, exposed panels, "
        "default credentials, and more."
    )
    binary = "nuclei"

    def build_args(self, **kwargs: Any) -> list[str]:
        args = ["-silent", "-jsonl"]

        if kwargs.get("target"):
            args.extend(["-u", kwargs["target"]])
        elif kwargs.get("list"):
            args.extend(["-l", kwargs["list"]])

        if kwargs.get("templates"):
            args.extend(["-t", kwargs["templates"]])
        if kwargs.get("tags"):
            args.extend(["-tags", kwargs["tags"]])
        if kwargs.get("severity"):
            args.extend(["-severity", kwargs["severity"]])
        if kwargs.get("rate_limit"):
            args.extend(["-rl", str(kwargs["rate_limit"])])
        if kwargs.get("automatic_scan"):
            args.append("-as")

        return args

    def openai_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Single target URL to scan",
                    },
                    "list": {
                        "type": "string",
                        "description": "Path to file containing list of target URLs",
                    },
                    "templates": {
                        "type": "string",
                        "description": "Path to specific template or template directory",
                    },
                    "tags": {
                        "type": "string",
                        "description": "Execute templates with matching tags (e.g. 'cve,misconfig,exposure')",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity (e.g. 'critical,high,medium')",
                    },
                    "rate_limit": {
                        "type": "integer",
                        "description": "Maximum requests per second",
                        "default": 150,
                    },
                    "automatic_scan": {
                        "type": "boolean",
                        "description": "Enable automatic web scan using Wappalyzer technology detection",
                        "default": False,
                    },
                },
                "required": [],
            },
        }


registry.register(NucleiTool())
