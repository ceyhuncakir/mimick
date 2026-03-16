"""Report generation and output management."""

from datetime import datetime, timezone
from pathlib import Path

from mimick.config import settings
from mimick.logger import get_logger

log = get_logger("reporter")


def save_report(target: str, report: str, run_id: str = "") -> Path:
    """Save a markdown report to the output directory."""
    output_dir = settings.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    filename = f"mimick_{safe_target}_{timestamp}.md"

    path = output_dir / filename

    script_note = ""
    if run_id:
        script_name = f"validation/{run_id}_validate.py"
        script_note = f"\n**Validation Script:** `python3 {script_name}`\n"

    content = f"""# Mimick Pentest Report

    **Target:** {target}
    **Date:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
    **Tool:** Mimick v0.1.0
    {script_note}
    ---

    {report}
    """

    path.write_text(content)
    log.info("Report written to %s (%d bytes)", path, len(content))
    return path
