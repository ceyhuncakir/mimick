"""Dalfox - parameter analysis and XSS scanner."""

from typing import Any

from mimick.tools.base import Tool, registry


class DalfoxTool(Tool):
    name = "dalfox"
    description = (
        "Automated XSS vulnerability scanner with smart payload generation. "
        "Tests reflected, stored, and DOM-based XSS with WAF bypass techniques. "
        "Supports parameter analysis, blind XSS with callback, and headless verification."
    )
    binary = "dalfox"

    def build_args(self, **kwargs: Any) -> list[str]:
        mode = kwargs.get("mode", "url")
        args = [mode]

        if mode == "url" and kwargs.get("url"):
            args.append(kwargs["url"])
        elif mode == "file" and kwargs.get("list"):
            args.append(kwargs["list"])
        elif mode == "pipe":
            pass  # reads from stdin

        if kwargs.get("data"):
            args.extend(["-d", kwargs["data"]])
        if kwargs.get("cookie"):
            args.extend(["-C", kwargs["cookie"]])
        if kwargs.get("headers"):
            for h in kwargs["headers"]:
                args.extend(["-H", h])

        if kwargs.get("param"):
            args.extend(["-p", kwargs["param"]])

        # Blind XSS callback
        if kwargs.get("blind"):
            args.extend(["--blind", kwargs["blind"]])

        # WAF bypass
        if kwargs.get("waf_evasion"):
            args.append("--waf-evasion")

        # Mining options
        if kwargs.get("mining_dict"):
            args.append("--mining-dict")
        if kwargs.get("mining_dom"):
            args.append("--mining-dom")

        # Custom payloads
        if kwargs.get("custom_payload"):
            args.extend(["--custom-payload", kwargs["custom_payload"]])

        # Output format
        args.extend(["--format", "json"])

        # Timeout and workers
        if kwargs.get("timeout"):
            args.extend(["--timeout", str(kwargs["timeout"])])
        workers = kwargs.get("workers", 1)
        args.extend(["-w", str(workers)])

        # Silence banner
        args.append("--silence")

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
                        "description": (
                            "Target URL with parameters to test for XSS "
                            "(e.g. 'https://example.com/search?q=test')"
                        ),
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["url", "file"],
                        "description": "Scan mode: 'url' for single URL, 'file' for URL list (default: url)",
                        "default": "url",
                    },
                    "list": {
                        "type": "string",
                        "description": "Path to file with URLs to scan (when mode='file')",
                    },
                    "param": {
                        "type": "string",
                        "description": "Specific parameter to test (e.g. 'q'). Tests all by default.",
                    },
                    "data": {
                        "type": "string",
                        "description": "POST data for testing POST-based XSS",
                    },
                    "cookie": {
                        "type": "string",
                        "description": "Cookie string for authenticated testing",
                    },
                    "headers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "HTTP headers as 'Key: Value' strings",
                    },
                    "blind": {
                        "type": "string",
                        "description": (
                            "Blind XSS callback URL (e.g. your interactsh URL). "
                            "Dalfox will inject payloads that call back to this URL."
                        ),
                    },
                    "waf_evasion": {
                        "type": "boolean",
                        "description": "Enable WAF evasion techniques (default: false)",
                        "default": False,
                    },
                    "mining_dict": {
                        "type": "boolean",
                        "description": "Enable dictionary-based parameter mining (default: false)",
                        "default": False,
                    },
                    "mining_dom": {
                        "type": "boolean",
                        "description": "Enable DOM-based mining for potential XSS sinks (default: false)",
                        "default": False,
                    },
                    "custom_payload": {
                        "type": "string",
                        "description": "Custom XSS payload to test",
                    },
                    "workers": {
                        "type": "integer",
                        "description": "Number of concurrent workers (default: 1)",
                        "default": 1,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds for each request (default: 10)",
                        "default": 10,
                    },
                },
                "required": [],
            },
        }


registry.register(DalfoxTool())
