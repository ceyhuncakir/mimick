"""ffuf - fast web fuzzer for directory/file discovery and parameter fuzzing."""

import json
from typing import Any

from cannon.tools.base import Tool, registry


class FfufTool(Tool):
    name = "ffuf"
    description = (
        "Fast web fuzzer. Discovers hidden directories, files, vhosts, "
        "and parameters by fuzzing with wordlists. Use FUZZ keyword in the URL."
    )
    binary = "ffuf"

    def build_args(self, **kwargs: Any) -> list[str]:
        args = ["-u", kwargs["url"], "-w", kwargs["wordlist"], "-of", "json", "-o", "/dev/stdout", "-s"]

        if kwargs.get("method"):
            args.extend(["-X", kwargs["method"]])
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])
        if kwargs.get("filter_code"):
            args.extend(["-fc", kwargs["filter_code"]])
        if kwargs.get("match_code"):
            args.extend(["-mc", kwargs["match_code"]])
        if kwargs.get("filter_size"):
            args.extend(["-fs", kwargs["filter_size"]])
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])
        if kwargs.get("rate"):
            args.extend(["-rate", str(kwargs["rate"])])
        if kwargs.get("extensions"):
            args.extend(["-e", kwargs["extensions"]])
        if kwargs.get("data"):
            args.extend(["-d", kwargs["data"]])
        if kwargs.get("recursion"):
            args.append("-recursion")

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
                        "description": "Target URL with FUZZ keyword (e.g. 'https://example.com/FUZZ')",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to wordlist file (e.g. '/usr/share/wordlists/dirb/common.txt')",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method to use (GET, POST, PUT, etc.)",
                        "default": "GET",
                    },
                    "headers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "HTTP headers to add (e.g. ['Authorization: Bearer token'])",
                    },
                    "filter_code": {
                        "type": "string",
                        "description": "Filter out HTTP status codes (e.g. '404,403')",
                    },
                    "match_code": {
                        "type": "string",
                        "description": "Match HTTP status codes (e.g. '200,301,302')",
                    },
                    "filter_size": {
                        "type": "string",
                        "description": "Filter out response sizes",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads",
                        "default": 40,
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Rate of requests per second",
                    },
                    "extensions": {
                        "type": "string",
                        "description": "File extensions to append (e.g. '.php,.html,.js,.txt')",
                    },
                    "data": {
                        "type": "string",
                        "description": "POST data (e.g. 'username=FUZZ&password=test')",
                    },
                    "recursion": {
                        "type": "boolean",
                        "description": "Enable recursion for directory discovery",
                        "default": False,
                    },
                },
                "required": ["url", "wordlist"],
            },
        }

    def parse_output(self, stdout: str) -> dict | None:
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return None


registry.register(FfufTool())
