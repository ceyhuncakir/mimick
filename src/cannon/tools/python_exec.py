"""python_exec - Write and execute Python scripts, returning their output."""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path
from typing import Any

from cannon.config import settings
from cannon.tools.base import Tool, ToolResult, registry


class PythonExecTool(Tool):
    name = "python_exec"
    description = (
        "Write and execute a Python script. Use this for custom logic: "
        "parsing data, transforming tool output, crafting payloads, "
        "making complex HTTP requests, or any task the other tools can't handle. "
        "The script's stdout and stderr are returned."
    )
    binary = sys.executable

    def build_args(self, **kwargs: Any) -> list[str]:
        raise NotImplementedError("PythonExecTool overrides run() directly.")

    def openai_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "The Python source code to execute.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Max execution time in seconds.",
                        "default": 60,
                    },
                },
                "required": ["code"],
            },
        }

    def is_available(self) -> bool:
        return True

    async def run(self, **kwargs: Any) -> ToolResult:
        from cannon.logger import get_logger

        log = get_logger(f"tool.{self.name}")

        code: str = kwargs["code"]
        timeout: int = min(kwargs.get("timeout", 60), 300)

        # Write script to workspace so it's inspectable after the run
        workspace = settings.output_dir / "scripts"
        workspace.mkdir(parents=True, exist_ok=True)

        script = tempfile.NamedTemporaryFile(
            dir=workspace, prefix="cannon_", suffix=".py",
            mode="w", delete=False,
        )
        script.write(code)
        script.close()
        script_path = Path(script.name)

        log.debug("Wrote script to %s", script_path)

        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary, str(script_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ToolResult(
                tool_name=self.name,
                command=f"python {script_path.name}",
                stdout="",
                stderr=f"Script timed out after {timeout}s",
                return_code=1,
            )

        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")

        log.debug(
            "Exit code: %d | stdout: %d bytes | stderr: %d bytes",
            proc.returncode or 0, len(stdout), len(stderr),
        )

        return ToolResult(
            tool_name=self.name,
            command=f"python {script_path.name}",
            stdout=stdout,
            stderr=stderr,
            return_code=proc.returncode or 0,
        )


registry.register(PythonExecTool())
