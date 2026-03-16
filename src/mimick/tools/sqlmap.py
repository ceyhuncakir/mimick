"""SQLMap - automated SQL injection detection and exploitation."""

from typing import Any

from mimick.tools.base import Tool, registry


class SqlmapTool(Tool):
    name = "sqlmap"
    description = (
        "Automated SQL injection scanner. Tests for boolean-blind, time-blind, "
        "error-based, UNION-based, and stacked queries injection. Supports "
        "WAF bypass with tamper scripts. Much more thorough than manual SQLi testing."
    )
    binary = "sqlmap"

    def build_args(self, **kwargs: Any) -> list[str]:
        args = []

        if kwargs.get("url"):
            args.extend(["-u", kwargs["url"]])
        if kwargs.get("request_file"):
            args.extend(["-r", kwargs["request_file"]])

        if kwargs.get("data"):
            args.extend(["--data", kwargs["data"]])
        if kwargs.get("cookie"):
            args.extend(["--cookie", kwargs["cookie"]])
        if kwargs.get("headers"):
            for h in kwargs["headers"]:
                args.extend(["-H", h])

        if kwargs.get("param"):
            args.extend(["-p", kwargs["param"]])

        # Technique selection
        if kwargs.get("technique"):
            args.extend(["--technique", kwargs["technique"]])

        # Risk and level control
        level = kwargs.get("level", 1)
        risk = kwargs.get("risk", 1)
        args.extend(["--level", str(level), "--risk", str(risk)])

        # WAF bypass
        if kwargs.get("tamper"):
            args.extend(["--tamper", kwargs["tamper"]])
        if kwargs.get("random_agent", True):
            args.append("--random-agent")

        # Database enumeration
        if kwargs.get("dbs"):
            args.append("--dbs")
        if kwargs.get("tables"):
            args.append("--tables")
        if kwargs.get("dump"):
            args.append("--dump")
        if kwargs.get("current_db"):
            args.append("--current-db")
        if kwargs.get("current_user"):
            args.append("--current-user")

        # Always non-interactive, with output
        args.extend(["--batch", "--flush-session"])

        # Timeout
        timeout = kwargs.get("timeout", 30)
        args.extend(["--timeout", str(timeout)])

        # Threads
        threads = kwargs.get("threads", 1)
        args.extend(["--threads", str(threads)])

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
                            "Target URL with injectable parameter marked by * or "
                            "with query string (e.g. 'https://example.com/page?id=1')"
                        ),
                    },
                    "request_file": {
                        "type": "string",
                        "description": "Path to file with raw HTTP request (alternative to url)",
                    },
                    "data": {
                        "type": "string",
                        "description": "POST data string (e.g. 'username=admin&password=test')",
                    },
                    "param": {
                        "type": "string",
                        "description": "Specific parameter to test (e.g. 'id'). Tests all by default.",
                    },
                    "cookie": {
                        "type": "string",
                        "description": "HTTP cookie string for authenticated testing",
                    },
                    "headers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "HTTP headers as 'Key: Value' strings",
                    },
                    "technique": {
                        "type": "string",
                        "description": (
                            "SQLi techniques to test: B=boolean, E=error, U=union, "
                            "S=stacked, T=time-blind, Q=inline (e.g. 'BEUST' for all)"
                        ),
                    },
                    "level": {
                        "type": "integer",
                        "description": "Testing level 1-5. Higher=more payloads, slower (default: 1)",
                        "default": 1,
                    },
                    "risk": {
                        "type": "integer",
                        "description": "Risk level 1-3. Higher=more aggressive payloads (default: 1)",
                        "default": 1,
                    },
                    "tamper": {
                        "type": "string",
                        "description": (
                            "WAF bypass tamper scripts, comma-separated "
                            "(e.g. 'space2comment,between,randomcase')"
                        ),
                    },
                    "random_agent": {
                        "type": "boolean",
                        "description": "Use random User-Agent header (default: true)",
                        "default": True,
                    },
                    "dbs": {
                        "type": "boolean",
                        "description": "Enumerate databases after finding injection",
                        "default": False,
                    },
                    "tables": {
                        "type": "boolean",
                        "description": "Enumerate tables after finding injection",
                        "default": False,
                    },
                    "current_db": {
                        "type": "boolean",
                        "description": "Get current database name",
                        "default": False,
                    },
                    "current_user": {
                        "type": "boolean",
                        "description": "Get current database user",
                        "default": False,
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Max concurrent requests (default: 1)",
                        "default": 1,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Seconds to wait for each HTTP response (default: 30)",
                        "default": 30,
                    },
                },
                "required": [],
            },
        }


registry.register(SqlmapTool())
