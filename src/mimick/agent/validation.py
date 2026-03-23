from __future__ import annotations

import importlib.resources
import json
import shutil
from pathlib import Path
from typing import Any

from mimick.logger import get_logger
from mimick.memory.store import ExperienceStore
from mimick.tracker import AttackTracker

log = get_logger("agent.validation")


def sync_validation_to_experiences(
    store: ExperienceStore, validation_results: list[dict[str, str]]
) -> None:
    """Mark experiences as unvalidated if their findings failed validation.

    Args:
        store: The experience store to update.
        validation_results: List of validation result dicts with
            ``status`` and ``title`` keys.
    """
    for result in validation_results:
        if result["status"] == "UNCONFIRMED":
            matches = store.query(result.get("title", ""), top_k=1)
            for exp in matches:
                if exp.finding_title.lower() == result.get("title", "").lower():
                    exp.validated = False
                    store._collection.update(
                        ids=[exp.id],
                        metadatas=[exp.metadata_dict()],
                    )
                    log.info(
                        "Experience %s marked unvalidated: %s",
                        exp.id,
                        exp.finding_title,
                    )


def format_validation_section(results: list[dict[str, str]]) -> str:
    """Render validation results as a Markdown table.

    Args:
        results: List of validation result dicts.

    Returns:
        Markdown-formatted validation summary.
    """
    status_icons: dict[str, str] = {
        "CONFIRMED": "\u2705",
        "UNCONFIRMED": "\u26a0\ufe0f",
        "ERROR": "\u274c",
    }
    lines: list[str] = [
        "\n\n## Validation Results\n",
        "| # | Severity | Finding | Status | Detail |",
        "|---|----------|---------|--------|--------|",
    ]
    for i, r in enumerate(results, 1):
        icon: str = status_icons.get(r["status"], "?")
        sev: str = r["severity"].upper() if r["severity"] else "\u2014"
        lines.append(
            f"| {i} | {sev} | {r['title'][:50].replace('|', '\\|')} "
            f"| {icon} {r['status']} | {r['detail'][:80].replace('|', '\\|')} |"
        )

    confirmed: int = sum(1 for r in results if r["status"] == "CONFIRMED")
    lines.append(
        f"\n**{confirmed}/{len(results)}** findings independently confirmed.\n"
    )
    return "\n".join(lines)


def write_validation_script(
    tracker: AttackTracker,
    results: list[dict[str, str]],
    output_dir: Path,
    run_id: str,
) -> Path:
    """Copy the standalone validator script and write a findings JSON sidecar.

    Args:
        tracker: The attack tracker containing finding nodes.
        results: Validation results (drives the generation decision).
        output_dir: Directory to write into.
        run_id: Unique identifier for this assessment run.

    Returns:
        Path to the copied validation script.
    """
    findings_data: list[dict[str, Any]] = [
        {
            "id": node.id,
            "title": node.label,
            "severity": node.data.get("severity", ""),
            "url": node.data.get("url", ""),
            "reproduction": node.data.get("reproduction", []),
        }
        for node in tracker._nodes
        if node.type == "finding"
    ]

    val_dir: Path = output_dir / "validation"
    val_dir.mkdir(parents=True, exist_ok=True)

    findings_path: Path = val_dir / f"{run_id}_findings.json"
    findings_path.write_text(json.dumps(findings_data, indent=2))

    script_src = importlib.resources.files("mimick.templates").joinpath("validate.py")
    script_dst: Path = val_dir / f"{run_id}_validate.py"
    with importlib.resources.as_file(script_src) as src_path:
        shutil.copy2(src_path, script_dst)
    script_dst.chmod(0o755)

    return script_dst
