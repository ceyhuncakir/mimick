from __future__ import annotations

from pathlib import Path
from typing import Any

from mimick.tools.base import Tool, ToolResult, registry

DOCS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "docs"

ALIASES: dict[str, str] = {
    "sqli": "SQL Injection",
    "sql": "SQL Injection",
    "sql injection": "SQL Injection",
    "xss": "XSS Injection",
    "cross site scripting": "XSS Injection",
    "xxe": "XXE Injection",
    "xml external entity": "XXE Injection",
    "ssrf": "Server Side Request Forgery",
    "ssti": "Server Side Template Injection",
    "template injection": "Server Side Template Injection",
    "csrf": "Cross-Site Request Forgery",
    "cross site request forgery": "Cross-Site Request Forgery",
    "idor": "Insecure Direct Object References",
    "insecure direct object reference": "Insecure Direct Object References",
    "rce": "Command Injection",
    "command injection": "Command Injection",
    "os injection": "Command Injection",
    "lfi": "File Inclusion",
    "rfi": "File Inclusion",
    "file inclusion": "File Inclusion",
    "local file inclusion": "File Inclusion",
    "path traversal": "Directory Traversal",
    "directory traversal": "Directory Traversal",
    "cors": "CORS Misconfiguration",
    "open redirect": "Open Redirect",
    "redirect": "Open Redirect",
    "jwt": "JSON Web Token",
    "json web token": "JSON Web Token",
    "deserialization": "Insecure Deserialization",
    "upload": "Upload Insecure Files",
    "file upload": "Upload Insecure Files",
    "nosql": "NoSQL Injection",
    "nosql injection": "NoSQL Injection",
    "graphql": "GraphQL Injection",
    "oauth": "OAuth Misconfiguration",
    "race condition": "Race Condition",
    "request smuggling": "Request Smuggling",
    "http smuggling": "Request Smuggling",
    "prototype pollution": "Prototype Pollution",
    "crlf": "CRLF Injection",
    "clickjacking": "Clickjacking",
    "mass assignment": "Mass Assignment",
    "saml": "SAML Injection",
    "ssi": "Server Side Include Injection",
    "xpath": "XPATH Injection",
    "xslt": "XSLT Injection",
    "xxe injection": "XXE Injection",
    "dns rebinding": "DNS Rebinding",
    "cache deception": "Web Cache Deception",
    "web cache": "Web Cache Deception",
    "websocket": "Web Sockets",
    "websockets": "Web Sockets",
    "zip slip": "Zip Slip",
    "account takeover": "Account Takeover",
    "api key": "API Key Leaks",
    "brute force": "Brute Force Rate Limit",
    "rate limit": "Brute Force Rate Limit",
    "business logic": "Business Logic Errors",
    "ldap": "LDAP Injection",
    "latex": "LaTeX Injection",
    "type juggling": "Type Juggling",
    "csv injection": "CSV Injection",
    "css injection": "CSS Injection",
    "dom clobbering": "DOM Clobbering",
    "hidden parameters": "Hidden Parameters",
    "hpp": "HTTP Parameter Pollution",
    "parameter pollution": "HTTP Parameter Pollution",
    "subdomain takeover": "Virtual Hosts",
    "vhost": "Virtual Hosts",
    "reverse proxy": "Reverse Proxy Misconfigurations",
}


def _list_categories() -> list[str]:
    if not DOCS_DIR.is_dir():
        return []
    return sorted(
        d.name for d in DOCS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")
    )


def _find_category(query: str) -> Path | None:
    q = query.lower().strip()

    if q in ALIASES:
        candidate = DOCS_DIR / ALIASES[q]
        if candidate.is_dir():
            return candidate

    for d in DOCS_DIR.iterdir():
        if d.is_dir() and d.name.lower() == q:
            return d

    matches = []
    for d in DOCS_DIR.iterdir():
        if d.is_dir() and q in d.name.lower():
            matches.append(d)
    if len(matches) == 1:
        return matches[0]

    query_words = set(q.split())
    best_score = 0
    best_dir = None
    for d in DOCS_DIR.iterdir():
        if not d.is_dir():
            continue
        dir_words = set(d.name.lower().split())
        score = len(query_words & dir_words)
        if score > best_score:
            best_score = score
            best_dir = d
    if best_score > 0:
        return best_dir

    return None


def _find_subfile(category_dir: Path, query: str) -> Path | None:
    q = query.lower().strip()
    md_files = list(category_dir.glob("*.md"))

    for f in md_files:
        if f.name == "README.md":
            continue
        if q in f.stem.lower():
            return f

    return None


def _read_md(path: Path, max_chars: int = 30000) -> str:
    text = path.read_text(errors="replace")
    if len(text) <= max_chars:
        return text
    return (
        text[:max_chars] + f"\n\n... (truncated, {len(text) - max_chars} chars omitted)"
    )


class VulnLookupTool(Tool):
    name = "vuln_lookup"
    description = (
        "Search the vulnerability knowledge base for payloads, exploitation "
        "techniques, and bypass methods. Query with a vulnerability type "
        "(e.g. 'sqli', 'xss', 'ssrf') or a specific subtopic "
        "(e.g. 'mysql injection', 'jwt bypass', 'blind sqli'). "
        "Returns detailed cheatsheets with real payloads."
    )
    binary = ""

    def is_available(self) -> bool:
        return DOCS_DIR.is_dir()

    async def run(self, **kwargs: Any) -> ToolResult:
        query: str = kwargs["query"]
        subtopic: str | None = kwargs.get("subtopic")

        category_dir = _find_category(query)

        if not category_dir:
            categories = _list_categories()
            return ToolResult(
                tool_name=self.name,
                command=f"vuln_lookup {query}",
                stdout=f"No docs found for '{query}'.\n\nAvailable categories:\n"
                + "\n".join(f"  - {c}" for c in categories),
                stderr="",
                return_code=1,
            )

        sub_files = sorted(
            f.stem for f in category_dir.glob("*.md") if f.name != "README.md"
        )

        if subtopic:
            sub_path = _find_subfile(category_dir, subtopic)
            if sub_path:
                content = _read_md(sub_path)
                if sub_files:
                    content += f"\n\n---\nOther subtopics in {category_dir.name}: {', '.join(sub_files)}"
                return ToolResult(
                    tool_name=self.name,
                    command=f"vuln_lookup {query} > {subtopic}",
                    stdout=content,
                    stderr="",
                    return_code=0,
                )
            readme = category_dir / "README.md"
            if readme.is_file():
                content = _read_md(readme)
                content += (
                    f"\n\n---\nSubtopic '{subtopic}' not found. "
                    f"Available subtopics: {', '.join(sub_files) if sub_files else 'none'}"
                )
                return ToolResult(
                    tool_name=self.name,
                    command=f"vuln_lookup {query} > {subtopic}",
                    stdout=content,
                    stderr="",
                    return_code=0,
                )

        readme = category_dir / "README.md"
        if readme.is_file():
            content = _read_md(readme)
            if sub_files:
                content += (
                    "\n\n---\nSubtopics available (use subtopic parameter): "
                    + ", ".join(sub_files)
                )
            return ToolResult(
                tool_name=self.name,
                command=f"vuln_lookup {query}",
                stdout=content,
                stderr="",
                return_code=0,
            )

        md_files = sorted(category_dir.glob("*.md"))
        if md_files:
            content = _read_md(md_files[0])
            return ToolResult(
                tool_name=self.name,
                command=f"vuln_lookup {query}",
                stdout=content,
                stderr="",
                return_code=0,
            )

        return ToolResult(
            tool_name=self.name,
            command=f"vuln_lookup {query}",
            stdout=f"Category '{category_dir.name}' exists but has no markdown files.",
            stderr="",
            return_code=1,
        )


registry.register(VulnLookupTool())
