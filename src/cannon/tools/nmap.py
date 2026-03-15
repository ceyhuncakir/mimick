"""Nmap - network port scanner and service detection."""

from typing import Any

from cannon.tools.base import Tool, registry


class NmapTool(Tool):
    name = "nmap"
    description = (
        "Network scanner for port discovery and service/version detection. "
        "Identifies open ports, running services, and OS fingerprinting."
    )
    binary = "nmap"

    def build_args(self, **kwargs: Any) -> list[str]:
        args = []

        if kwargs.get("scan_type"):
            scan_map = {
                "syn": "-sS",
                "connect": "-sT",
                "udp": "-sU",
                "version": "-sV",
                "ping": "-sn",
            }
            flag = scan_map.get(kwargs["scan_type"], "-sT")
            args.append(flag)

        if kwargs.get("ports"):
            args.extend(["-p", kwargs["ports"]])
        if kwargs.get("top_ports"):
            args.extend(["--top-ports", str(kwargs["top_ports"])])
        if kwargs.get("service_detection"):
            if "-sV" not in args:
                args.append("-sV")
        if kwargs.get("os_detection"):
            args.append("-O")
        if kwargs.get("scripts"):
            args.extend(["--script", kwargs["scripts"]])
        if kwargs.get("timing"):
            args.append(f"-T{kwargs['timing']}")
        else:
            args.append("-T4")

        args.append(kwargs["target"])
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
                        "description": "Target IP, hostname, or CIDR range to scan",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port range to scan (e.g. '1-1000', '80,443,8080')",
                    },
                    "top_ports": {
                        "type": "integer",
                        "description": "Scan top N most common ports",
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["syn", "connect", "udp", "version", "ping"],
                        "description": "Type of scan to perform",
                        "default": "connect",
                    },
                    "service_detection": {
                        "type": "boolean",
                        "description": "Enable service/version detection (-sV)",
                        "default": True,
                    },
                    "os_detection": {
                        "type": "boolean",
                        "description": "Enable OS detection (-O, may require root)",
                        "default": False,
                    },
                    "scripts": {
                        "type": "string",
                        "description": "NSE scripts to run (e.g. 'vuln', 'default,safe', 'http-enum')",
                    },
                    "timing": {
                        "type": "integer",
                        "description": "Timing template 0-5 (higher = faster, noisier)",
                        "default": 4,
                    },
                },
                "required": ["target"],
            },
        }


registry.register(NmapTool())
