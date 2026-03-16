"""Arjun - HTTP parameter discovery tool."""

from typing import Any

from cannon.tools.base import Tool, registry


class ArjunTool(Tool):
    name = "arjun"
    description = (
        "Discovers hidden HTTP parameters (GET, POST, JSON, XML) on endpoints. "
        "Finds injection points that aren't visible in the HTML or API docs. "
        "Essential for finding SQLi, XSS, SSRF entry points."
    )
    binary = "arjun"

    def build_args(self, **kwargs: Any) -> list[str]:
        args = []

        if kwargs.get("url"):
            args.extend(["-u", kwargs["url"]])
        if kwargs.get("list"):
            args.extend(["-i", kwargs["list"]])

        method = kwargs.get("method", "GET")
        args.extend(["-m", method])

        if kwargs.get("headers"):
            for h in kwargs["headers"]:
                args.extend(["--headers", h])

        if kwargs.get("wordlist"):
            args.extend(["-w", kwargs["wordlist"]])

        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])

        # JSON output for structured parsing
        args.append("--json")

        # Stable output
        args.append("--stable")

        return args

    def openai_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to discover parameters on (e.g. 'https://example.com/api/users')",
                    },
                    "list": {
                        "type": "string",
                        "description": "Path to file containing list of URLs to test",
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "JSON", "XML"],
                        "description": "HTTP method / parameter type to discover (default: GET)",
                        "default": "GET",
                    },
                    "headers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "HTTP headers as 'Key: Value' strings",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Custom wordlist for parameter names (uses built-in by default)",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads (default: 2)",
                        "default": 2,
                    },
                },
                "required": [],
            },
        }


registry.register(ArjunTool())
