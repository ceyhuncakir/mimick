"""Katana - web crawling and spidering framework."""

from typing import Any

from mimick.tools.base import Tool, registry


class KatanaTool(Tool):
    name = "katana"
    description = (
        "Fast web crawler that discovers URLs, endpoints, and JavaScript files. "
        "Supports headless browsing and passive/active crawling modes."
    )
    binary = "katana"

    def build_args(self, **kwargs: Any) -> list[str]:
        args = ["-silent", "-jsonl"]

        if kwargs.get("target"):
            args.extend(["-u", kwargs["target"]])
        elif kwargs.get("list"):
            args.extend(["-list", kwargs["list"]])

        if kwargs.get("depth"):
            args.extend(["-d", str(kwargs["depth"])])
        if kwargs.get("js_crawl"):
            args.append("-jc")
        if kwargs.get("headless"):
            args.append("-headless")
        if kwargs.get("scope"):
            args.extend(["-cs", kwargs["scope"]])
        if kwargs.get("extensions_filter"):
            args.extend(["-ef", kwargs["extensions_filter"]])

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
                        "description": "Target URL to crawl",
                    },
                    "list": {
                        "type": "string",
                        "description": "Path to file with URLs to crawl",
                    },
                    "depth": {
                        "type": "integer",
                        "description": "Maximum crawl depth",
                        "default": 3,
                    },
                    "js_crawl": {
                        "type": "boolean",
                        "description": "Enable JavaScript file parsing and endpoint extraction",
                        "default": True,
                    },
                    "headless": {
                        "type": "boolean",
                        "description": "Use headless browser for JavaScript-rendered pages",
                        "default": False,
                    },
                    "scope": {
                        "type": "string",
                        "description": "Crawl scope regex (e.g. '.*\\.example\\.com')",
                    },
                    "extensions_filter": {
                        "type": "string",
                        "description": "Extensions to filter out (e.g. 'png,jpg,gif,css')",
                    },
                },
                "required": [],
            },
        }


registry.register(KatanaTool())
