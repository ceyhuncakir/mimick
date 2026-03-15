"""wafw00f - Web Application Firewall detection tool."""

from typing import Any

from cannon.tools.base import Tool, registry


class Wafw00fTool(Tool):
    name = "wafw00f"
    description = (
        "Detects Web Application Firewalls (WAFs) protecting a target. "
        "Identifies WAF vendor and type, useful for adjusting attack strategies."
    )
    binary = "wafw00f"

    def build_args(self, **kwargs: Any) -> list[str]:
        args = [kwargs["target"]]
        if kwargs.get("scan_all"):
            args.append("-a")
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
                        "description": "Target URL to check for WAF (e.g. 'https://example.com')",
                    },
                    "scan_all": {
                        "type": "boolean",
                        "description": "Test against all known WAFs instead of stopping at first match",
                        "default": False,
                    },
                },
                "required": ["target"],
            },
        }


registry.register(Wafw00fTool())
