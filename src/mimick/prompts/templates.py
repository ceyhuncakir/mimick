"""Prompt templates for specific pentesting tasks and workflows."""

RECON_PLAN = """\
Starting recon on the target.

Plan:
1. Enumerate subdomains with subfinder
2. Probe live hosts with httpx (status codes, tech, titles)
3. WAF detection with wafw00f
4. Port scan high-value hosts with nmap

Goal: map the attack surface before probing for bugs.\
"""

DISCOVERY_PLAN = """\
Recon complete. Live hosts: {host_count}. Tech: {technologies}.

Plan:
1. Crawl the app with katana (endpoints, JS, API routes)
2. Fuzz promising hosts with ffuf (directories, files)

Goal: find hidden endpoints and parameters to test.\
"""

VULN_SCAN_PLAN = """\
Discovery complete. Targets: {targets}. Tech: {technologies}.

Plan:
1. Run nuclei with templates matching the detected tech stack
2. Targeted manual testing on interesting endpoints
3. Custom scripts for business logic testing

Goal: find exploitable vulnerabilities.\
"""
