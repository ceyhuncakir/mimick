from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path
from typing import Any

from mimick.config import settings
from mimick.logger import get_logger
from mimick.tools.base import Tool, ToolResult, registry


class PythonExecTool(Tool):
    name = "python_exec"
    description = (
        "Write and execute a Python script. Use for custom logic: "
        "parsing, payloads, complex HTTP flows, Playwright browser automation."
    )
    binary = sys.executable

    def is_available(self) -> bool:
        return True

    async def run(self, **kwargs: Any) -> ToolResult:
        log = get_logger(f"tool.{self.name}")

        code: str = kwargs["code"]
        timeout: int = min(kwargs.get("timeout", 60), 300)

        workspace = settings.output_dir / "scripts"
        workspace.mkdir(parents=True, exist_ok=True)

        script = tempfile.NamedTemporaryFile(
            dir=workspace,
            prefix="mimick_",
            suffix=".py",
            mode="w",
            delete=False,
        )
        script.write(code)
        script.close()
        script_path = Path(script.name)
        log.debug("Wrote script to %s", script_path)

        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary,
                str(script_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
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

        return ToolResult(
            tool_name=self.name,
            command=f"python {script_path.name}",
            stdout=stdout_bytes.decode(errors="replace"),
            stderr=stderr_bytes.decode(errors="replace"),
            return_code=proc.returncode or 0,
        )


registry.register(PythonExecTool())
