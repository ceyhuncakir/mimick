"""Classify agent actions into human-readable strategy descriptions."""

from __future__ import annotations

import re
import shlex
from typing import Any

_NON_ATTACK_COMMANDS = frozenset({"ls", "cat", "echo", "which", "head", "tail", "wc"})

_PAYLOAD_PATTERNS: list[tuple[str, str]] = [
    ("{{", "SSTI payload"),
    ("UNION", "SQLi payload"),
    ("SELECT", "SQLi payload"),
    ("'", "SQLi payload"),
    ("<script", "XSS payload"),
    ("alert(", "XSS payload"),
    ("../", "path traversal payload"),
    ("etc/passwd", "path traversal payload"),
]

_PYTHON_KEYWORDS: list[tuple[str, str]] = [
    ("sqlmap", "SQLi testing"),
    ("sqli", "SQLi testing"),
    ("sql", "SQLi testing"),
    ("ssti", "SSTI testing"),
    ("{{7*7}}", "SSTI testing"),
    ("template", "SSTI testing"),
    ("xss", "XSS testing"),
    ("alert(", "XSS testing"),
    ("<script", "XSS testing"),
    ("traversal", "LFI/path traversal"),
    ("etc/passwd", "LFI/path traversal"),
    ("php://", "LFI/path traversal"),
    ("idor", "IDOR testing"),
    ("user_id", "IDOR testing"),
    ("other_user", "IDOR testing"),
    ("deseriali", "deserialization testing"),
    ("pickle", "deserialization testing"),
    ("unserialize", "deserialization testing"),
    ("session", "auth/session flow"),
    ("login", "auth/session flow"),
    ("register", "auth/session flow"),
]


def _find_cli_flag(parts: list[str], flag: str) -> str:
    """Return the value associated with *flag* in a tokenised command line.

    Args:
        parts: Shell-split command tokens.
        flag: The flag whose value to look up (e.g. ``"--level"``).

    Returns:
        The flag's value, or an empty string if the flag is absent.
    """
    for i, p in enumerate(parts):
        if p == flag and i + 1 < len(parts):
            return parts[i + 1]
        if p.startswith(f"{flag}="):
            return p.split("=", 1)[1]
    return ""


def extract_from_command(command: str) -> str:
    """Derive a strategy description from a raw shell command string.

    Args:
        command: The full shell command to analyse.

    Returns:
        A short human-readable label describing the attack strategy,
        or an empty string for non-attack commands.
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    if not parts:
        return ""

    tool = parts[0]
    if tool in _NON_ATTACK_COMMANDS or "--help" in command or "-h" in parts:
        return ""

    cmd_lower = command.lower()

    if tool == "sqlmap":
        level = _find_cli_flag(parts, "--level") or "1"
        risk = _find_cli_flag(parts, "--risk") or "1"
        tamper = _find_cli_flag(parts, "--tamper")
        desc = f"sqlmap (level={level}, risk={risk})"
        return f"{desc} tamper={tamper}" if tamper else desc

    if tool == "dalfox":
        mode = "blind" if "--blind" in cmd_lower else "standard"
        return f"dalfox XSS scan ({mode})"

    if tool == "curl":
        for pattern, label in _PAYLOAD_PATTERNS:
            if pattern in command or pattern.lower() in cmd_lower:
                method = _find_cli_flag(parts, "-X") or "GET"
                return f"curl {method} with {label}"
        method = _find_cli_flag(parts, "-X") or "GET"
        return f"curl {method}"

    simple_map = {
        "ffuf": "ffuf directory/file fuzzing",
        "nuclei": "nuclei vulnerability scan",
        "nmap": "nmap port scan",
        "katana": "katana web crawl",
    }
    return simple_map.get(tool, f"{tool} execution")


def extract_from_tool_call(tool_name: str, args: dict[str, Any]) -> str:
    """Derive a strategy description from a structured tool invocation.

    Args:
        tool_name: Name of the tool being called.
        args: Keyword arguments passed to the tool.

    Returns:
        A short human-readable label describing the attack strategy.
    """
    if tool_name == "sqlmap":
        level, risk = args.get("level", 1), args.get("risk", 1)
        tamper = args.get("tamper", "")
        param = args.get("param", "all params")
        desc = f"sqlmap on {param} (level={level}, risk={risk})"
        return f"{desc}, tamper={tamper}" if tamper else desc

    if tool_name == "dalfox":
        return f"dalfox XSS scan ({'blind' if args.get('blind') else 'standard'})"

    if tool_name == "curl":
        method = args.get("method", "GET")
        data = args.get("data", "")
        if data and len(data) > 20:
            data_lower = data.lower()
            for pattern, label in _PAYLOAD_PATTERNS:
                if pattern in data or pattern.lower() in data_lower:
                    return f"{method} with {label}"
            return f"{method} with custom payload"
        return f"curl {method}"

    if tool_name == "python_exec":
        code = args.get("code", "")[:200].lower()
        for keyword, label in _PYTHON_KEYWORDS:
            if keyword in code:
                return f"python script: {label}"
        return "python script: custom testing"

    if tool_name == "ffuf":
        return "ffuf directory/file fuzzing"
    if tool_name == "nuclei":
        tags = args.get("tags", "")
        templates = args.get("templates", "")
        return f"nuclei scan (tags={tags or 'auto'}, templates={templates or 'auto'})"
    if tool_name == "browser":
        return f"browser {args.get('action', '')}"

    return tool_name


def extract_url_from_command(command: str) -> str:
    """Extract the first HTTP(S) URL found in a shell command.

    Args:
        command: The raw shell command string.

    Returns:
        The matched URL, or an empty string if none is found.
    """
    match = re.search(r"https?://[^\s'\"]+", command)
    return match.group(0) if match else ""
