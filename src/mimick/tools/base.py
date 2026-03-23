"""Base abstractions for tool execution and registration."""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass
from typing import Any

from mimick.logger import get_logger


@dataclass
class ToolResult:
    """Represent the outcome of a single tool execution."""

    tool_name: str
    command: str
    stdout: str
    stderr: str
    return_code: int

    @property
    def success(self) -> bool:
        """Return True when the tool exited with code 0."""
        return self.return_code == 0

    def summary(self, max_lines: int = 200) -> str:
        """Return a human-readable summary of the result.

        Args:
            max_lines: Maximum number of stdout lines to include before
                truncating.

        Returns:
            A string containing the tool name, exit code, stdout (possibly
            truncated), and stderr on failure.
        """
        lines = self.stdout.strip().splitlines()
        if len(lines) > max_lines:
            output = "\n".join(
                lines[:max_lines]
                + [f"\n... ({len(lines) - max_lines} more lines truncated)"]
            )
        else:
            output = self.stdout.strip()

        parts = [f"[{self.tool_name}] exit_code={self.return_code}"]
        if output:
            parts.append(output)
        if self.stderr.strip() and not self.success:
            parts.append(f"STDERR: {self.stderr.strip()[:500]}")
        return "\n".join(parts)


class Tool:
    """Base class for an executable tool backed by a CLI binary."""

    name: str = ""
    description: str = ""
    binary: str = ""

    def is_available(self) -> bool:
        """Check whether the backing binary exists on PATH."""
        return bool(self.binary) and shutil.which(self.binary) is not None

    async def run(self, **kwargs: Any) -> ToolResult:
        """Execute the binary and return a ToolResult."""
        log = get_logger(f"tool.{self.name}")
        cmd = [self.binary]
        log.debug("Executing: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()

        return ToolResult(
            tool_name=self.name,
            command=" ".join(cmd),
            stdout=stdout_bytes.decode(errors="replace"),
            stderr=stderr_bytes.decode(errors="replace"),
            return_code=proc.returncode or 0,
        )


class ToolRegistry:
    """Central registry that maps tool names to Tool instances."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        """Register a tool under its name."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        """Return the tool registered under *name*, or None."""
        return self._tools.get(name)

    def all(self) -> list[Tool]:
        """Return every registered tool."""
        return list(self._tools.values())

    def available(self) -> list[Tool]:
        """Return only the registered tools whose binaries are present."""
        return [t for t in self._tools.values() if t.is_available()]


registry = ToolRegistry()
