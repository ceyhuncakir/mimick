import logging
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

MIMICK_THEME = Theme(
    {
        "logging.level.debug": "dim cyan",
        "logging.level.info": "bold green",
        "logging.level.warning": "bold yellow",
        "logging.level.error": "bold red",
        "logging.level.critical": "bold white on red",
        "mimick.tool": "bold cyan",
        "mimick.target": "bold magenta",
        "mimick.phase": "bold blue",
        "mimick.finding": "bold yellow",
        "mimick.success": "bold green",
        "mimick.fail": "bold red",
    }
)

console = Console(theme=MIMICK_THEME, stderr=True)

LOG_FORMAT = "%(message)s"
FILE_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
FILE_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(level: str = "INFO", log_file: Path | None = None) -> None:
    """Configure logging for the entire application."""
    log_level = getattr(logging, level.upper(), logging.INFO)

    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
        tracebacks_show_locals=False,
        log_time_format="[%H:%M:%S]",
    )
    rich_handler.setLevel(log_level)

    root = logging.getLogger("mimick")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()
    root.addHandler(rich_handler)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(FILE_FORMAT, datefmt=FILE_DATE_FORMAT)
        )
        root.addHandler(file_handler)

    logging.getLogger("litellm").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the 'mimick' namespace."""
    return logging.getLogger(f"mimick.{name}")
