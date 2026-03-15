"""Base tool class and tool registry for CLI security tools."""

from __future__ import annotations

import asyncio
import shutil
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolResult:
    """Result from a tool execution."""

    tool_name: str
    command: str
    stdout: str
    stderr: str
    return_code: int
    parsed: Any = None

    @property
    def success(self) -> bool:
        return self.return_code == 0

    def summary(self, max_lines: int = 200) -> str:
        """Return a truncated summary suitable for LLM context."""
        lines = self.stdout.strip().splitlines()
        if len(lines) > max_lines:
            truncated = lines[:max_lines]
            truncated.append(f"\n... ({len(lines) - max_lines} more lines truncated)")
            output = "\n".join(truncated)
        else:
            output = self.stdout.strip()

        parts = [f"[{self.tool_name}] exit_code={self.return_code}"]
        if output:
            parts.append(output)
        if self.stderr.strip() and not self.success:
            parts.append(f"STDERR: {self.stderr.strip()[:500]}")
        return "\n".join(parts)


class Tool(ABC):
    """Base class for all CLI security tools."""

    name: str
    description: str
    binary: str

    @abstractmethod
    def build_args(self, **kwargs: Any) -> list[str]:
        """Build command-line arguments from keyword arguments."""
        ...

    @abstractmethod
    def openai_schema(self) -> dict[str, Any]:
        """Return the OpenAI function/tool schema for this tool."""
        ...

    def is_available(self) -> bool:
        """Check if the underlying binary is installed."""
        return shutil.which(self.binary) is not None

    async def run(self, **kwargs: Any) -> ToolResult:
        """Execute the tool with the given arguments."""
        from cannon.logger import get_logger

        log = get_logger(f"tool.{self.name}")

        args = self.build_args(**kwargs)
        cmd = [self.binary] + args

        log.debug("Executing: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()

        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")

        parsed = self.parse_output(stdout)

        log.debug("Exit code: %d | stdout: %d bytes | stderr: %d bytes",
                   proc.returncode or 0, len(stdout), len(stderr))

        return ToolResult(
            tool_name=self.name,
            command=" ".join(cmd),
            stdout=stdout,
            stderr=stderr,
            return_code=proc.returncode or 0,
            parsed=parsed,
        )

    def parse_output(self, stdout: str) -> Any:
        """Parse tool output. Override for structured parsing."""
        return None


def _try_parse_jsonl(stdout: str) -> list[dict] | None:
    """Try to parse newline-delimited JSON output."""
    results = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            return None
    return results if results else None


class ToolRegistry:
    """Registry holding all available tools."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def all(self) -> list[Tool]:
        return list(self._tools.values())

    def available(self) -> list[Tool]:
        return [t for t in self._tools.values() if t.is_available()]

    def openai_tools_schema(self) -> list[dict[str, Any]]:
        """Return OpenAI-compatible tools list for function calling."""
        return [
            {"type": "function", "function": t.openai_schema()}
            for t in self._tools.values()
        ]


registry = ToolRegistry()
