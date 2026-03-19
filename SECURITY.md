# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Mimick itself (not findings produced by Mimick against a target), please report it responsibly.

**Do not open a public issue for security vulnerabilities.**

Instead, email **ceyhuncakir@live.nl** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact

I will acknowledge your report within 48 hours and aim to provide a fix or mitigation plan within 7 days.

## Scope

The following are in scope for security reports:

- Vulnerabilities in Mimick's own codebase (e.g., command injection in tool wrappers, unsafe deserialization, credential leakage)
- Issues where Mimick could be exploited by a malicious target (e.g., a target website triggering unintended behavior in the agent)
- Insecure handling of API keys, secrets, or scan results

The following are **out of scope**:

- Vulnerabilities found *by* Mimick in target applications — those are the tool working as intended
- Security issues in third-party tools (nmap, sqlmap, nuclei, etc.) — report those upstream

## Responsible Use

Mimick is designed for **authorized security testing only**. Users are responsible for:

- Obtaining proper written authorization before scanning any target
- Complying with all applicable laws and regulations
- Using the tool only within the agreed scope of an engagement

Unauthorized use of Mimick against systems you do not own or have permission to test is illegal and strictly prohibited.

## Supported Versions

Security fixes are applied to the latest version on the `main` branch. There are no long-term support branches at this time.
