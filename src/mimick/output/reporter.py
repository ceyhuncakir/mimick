"""Report generation in Markdown and PDF formats."""

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


def save_report_pdf(markdown_path: Path) -> Path:
    """Convert a markdown report to PDF."""
    import markdown
    from weasyprint import HTML

    md_content = markdown_path.read_text()
    html_body = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code", "codehilite", "toc"],
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    @page {{
        size: A4;
        margin: 2cm;
    }}
    body {{
        font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
        font-size: 11pt;
        line-height: 1.6;
        color: #1a1a1a;
    }}
    h1 {{
        font-size: 22pt;
        border-bottom: 2px solid #c0392b;
        padding-bottom: 8px;
        color: #c0392b;
    }}
    h2 {{
        font-size: 16pt;
        margin-top: 24px;
        color: #2c3e50;
        border-bottom: 1px solid #ddd;
        padding-bottom: 4px;
    }}
    h3 {{
        font-size: 13pt;
        color: #34495e;
    }}
    code {{
        background: #f4f4f4;
        padding: 2px 5px;
        border-radius: 3px;
        font-size: 10pt;
        font-family: "Courier New", monospace;
    }}
    pre {{
        background: #f4f4f4;
        padding: 12px;
        border-radius: 4px;
        overflow-x: auto;
        border-left: 3px solid #c0392b;
    }}
    pre code {{
        background: none;
        padding: 0;
    }}
    table {{
        border-collapse: collapse;
        width: 100%;
        margin: 16px 0;
    }}
    th, td {{
        border: 1px solid #ddd;
        padding: 8px 12px;
        text-align: left;
    }}
    th {{
        background: #2c3e50;
        color: white;
        font-weight: 600;
    }}
    tr:nth-child(even) {{
        background: #f9f9f9;
    }}
    strong {{
        color: #2c3e50;
    }}
    hr {{
        border: none;
        border-top: 1px solid #ddd;
        margin: 24px 0;
    }}
    blockquote {{
        border-left: 3px solid #c0392b;
        margin: 16px 0;
        padding: 8px 16px;
        background: #fdf2f2;
    }}
</style>
</head>
<body>
{html_body}
</body>
</html>"""

    pdf_path = markdown_path.with_suffix(".pdf")
    HTML(string=html).write_pdf(pdf_path)
    log.info("PDF report written to %s", pdf_path)
    return pdf_path
