"""Register external CLI binaries as simple Tool instances."""

from mimick.tools.base import Tool, registry


def _register(name: str, binary: str, description: str) -> None:
    """Create a generic Tool for *binary* and add it to the global registry."""
    tool = Tool()
    tool.name = name
    tool.binary = binary
    tool.description = description
    registry.register(tool)


_register(
    "subfinder",
    "subfinder",
    "Passive subdomain enumeration. Discovers subdomains of a target domain using passive sources.",
)

_register(
    "httpx",
    "httpx",
    "HTTP toolkit for probing URLs. Checks which hosts are alive, extracts status codes, titles, technologies, and more.",
)

_register(
    "nuclei",
    "nuclei",
    "Fast vulnerability scanner powered by YAML templates. Scans targets for known CVEs, misconfigurations, exposed panels, default credentials, and more.",
)

_register(
    "ffuf",
    "ffuf",
    "Fast web fuzzer. Discovers hidden directories, files, vhosts, and parameters by fuzzing with wordlists. Use FUZZ keyword in the URL.",
)

_register(
    "nmap",
    "nmap",
    "Network scanner for port discovery and service/version detection. Identifies open ports, running services, and OS fingerprinting.",
)

_register(
    "katana",
    "katana",
    "Fast web crawler that discovers URLs, endpoints, and JavaScript files. Supports headless browsing and passive/active crawling modes.",
)

_register(
    "wafw00f",
    "wafw00f",
    "Detects Web Application Firewalls (WAFs) protecting a target. Identifies WAF vendor and type, useful for adjusting attack strategies.",
)

_register(
    "curl",
    "curl",
    "Make HTTP requests to a URL. Supports GET, POST, PUT, DELETE, etc. Returns status code, headers, and response body. "
    "Useful for testing endpoints, submitting forms, checking APIs, and inspecting responses.",
)

_register(
    "interactsh-client",
    "interactsh-client",
    "Out-of-band (OOB) interaction server for detecting blind vulnerabilities. "
    "Use to get a unique callback URL, inject it into payloads (blind XSS, blind SSRF, blind XXE, blind SQLi, etc.), "
    "then poll to check if the target made any callbacks.",
)

_register(
    "arjun",
    "arjun",
    "Discovers hidden HTTP parameters (GET, POST, JSON, XML) on endpoints. "
    "Finds injection points that aren't visible in the HTML or API docs.",
)

_register(
    "sqlmap",
    "sqlmap",
    "Automated SQL injection scanner. Tests for boolean-blind, time-blind, error-based, UNION-based, and stacked queries injection. "
    "Supports WAF bypass with tamper scripts. Much more thorough than manual SQLi testing.",
)

_register(
    "dalfox",
    "dalfox",
    "Automated XSS vulnerability scanner with smart payload generation. Tests reflected, stored, and DOM-based XSS "
    "with WAF bypass techniques. Supports parameter analysis, blind XSS with callback, and headless verification.",
)

_register(
    "flask-unsign",
    "flask-unsign",
    "Crack and forge Flask session cookies. Use --unsign to brute-force the secret key, "
    "then --sign to forge cookies with arbitrary payloads.",
)
