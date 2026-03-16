"""Security tools - import all to register them with the registry."""

from cannon.tools.base import registry  # noqa: F401

# Importing each module triggers registry.register()
from cannon.tools import (  # noqa: F401
    subfinder,
    httpx_tool,
    nuclei,
    ffuf,
    nmap,
    katana,
    wafw00f,
    curl,
    python_exec,
    vuln_lookup,
    report_finding,
    spawn_agent,
    interactsh,
    arjun,
    sqlmap,
    dalfox,
    browser,
)
