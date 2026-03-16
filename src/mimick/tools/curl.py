"""curl - Make HTTP requests to URLs and inspect responses."""

from __future__ import annotations

from typing import Any

from mimick.tools.base import Tool, registry


class CurlTool(Tool):
    name = "curl"
    description = (
        "Make HTTP requests to a URL. Supports GET, POST, PUT, DELETE, etc. "
        "Returns status code, headers, and response body. Useful for testing "
        "endpoints, submitting forms, checking APIs, and inspecting responses."
    )
    binary = "curl"

    def build_args(self, **kwargs: Any) -> list[str]:
        args = ["-s", "-S", "-i"]  # silent, show errors, include headers

        if kwargs.get("max_time"):
            args.extend(["--max-time", str(kwargs["max_time"])])
        else:
            args.extend(["--max-time", "30"])

        method = kwargs.get("method", "GET").upper()
        args.extend(["-X", method])

        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])

        if kwargs.get("data"):
            args.extend(["-d", kwargs["data"]])

        if kwargs.get("follow_redirects"):
            args.extend(["-L", "--max-redirs", "10"])

        if kwargs.get("user_agent"):
            args.extend(["-A", kwargs["user_agent"]])

        if kwargs.get("cookie"):
            args.extend(["-b", kwargs["cookie"]])

        if kwargs.get("proxy"):
            args.extend(["-x", kwargs["proxy"]])

        # Allow insecure connections (self-signed certs)
        if kwargs.get("insecure"):
            args.append("-k")

        args.append(kwargs["url"])
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
                        "description": "The URL to send the request to",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)",
                        "default": "GET",
                    },
                    "headers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "HTTP headers as 'Key: Value' strings (e.g. ['Content-Type: application/json', 'Authorization: Bearer token'])",
                    },
                    "data": {
                        "type": "string",
                        "description": "Request body data. For JSON, pass a JSON string and set Content-Type header.",
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "Follow HTTP redirects (up to 10)",
                        "default": False,
                    },
                    "user_agent": {
                        "type": "string",
                        "description": "Custom User-Agent header",
                    },
                    "cookie": {
                        "type": "string",
                        "description": "Cookie string or path to cookie file",
                    },
                    "proxy": {
                        "type": "string",
                        "description": "Proxy URL (e.g. http://127.0.0.1:8080)",
                    },
                    "insecure": {
                        "type": "boolean",
                        "description": "Allow insecure SSL connections (skip certificate verification)",
                        "default": False,
                    },
                    "max_time": {
                        "type": "integer",
                        "description": "Maximum time in seconds for the request",
                        "default": 30,
                    },
                },
                "required": ["url"],
            },
        }


registry.register(CurlTool())
