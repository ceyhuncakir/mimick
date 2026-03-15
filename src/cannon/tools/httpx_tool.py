"""httpx (projectdiscovery) - HTTP probing and analysis tool."""

from typing import Any

from cannon.tools.base import Tool, _try_parse_jsonl, registry


class HttpxTool(Tool):
    name = "httpx"
    description = (
        "HTTP toolkit for probing URLs. Checks which hosts are alive, "
        "extracts status codes, titles, technologies, and more."
    )
    binary = "httpx"

    def build_args(self, **kwargs: Any) -> list[str]:
        args = ["-silent", "-json"]

        if kwargs.get("target"):
            args.extend(["-u", kwargs["target"]])
        elif kwargs.get("list"):
            args.extend(["-l", kwargs["list"]])

        if kwargs.get("status_code"):
            args.append("-sc")
        if kwargs.get("title"):
            args.append("-title")
        if kwargs.get("tech_detect"):
            args.append("-td")
        if kwargs.get("web_server"):
            args.append("-server")
        if kwargs.get("follow_redirects"):
            args.append("-fr")
        if kwargs.get("ports"):
            args.extend(["-ports", kwargs["ports"]])

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
                        "description": "Single target URL or host to probe",
                    },
                    "list": {
                        "type": "string",
                        "description": "Path to file containing list of hosts/URLs to probe",
                    },
                    "status_code": {
                        "type": "boolean",
                        "description": "Display HTTP status code",
                        "default": True,
                    },
                    "title": {
                        "type": "boolean",
                        "description": "Display page title",
                        "default": True,
                    },
                    "tech_detect": {
                        "type": "boolean",
                        "description": "Detect technologies using Wappalyzer",
                        "default": False,
                    },
                    "web_server": {
                        "type": "boolean",
                        "description": "Display web server name",
                        "default": False,
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "Follow HTTP redirects",
                        "default": True,
                    },
                    "ports": {
                        "type": "string",
                        "description": "Ports to probe (e.g. '80,443,8080,8443')",
                    },
                },
                "required": [],
            },
        }

    def parse_output(self, stdout: str) -> list[dict] | None:
        return _try_parse_jsonl(stdout)


registry.register(HttpxTool())
