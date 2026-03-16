<div align="center">

# Mimick

**Autonomous AI-powered web penetration testing agent**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PydanticAI](https://img.shields.io/badge/built%20with-PydanticAI-ff69b4.svg)](https://github.com/pydantic/pydantic-ai)

Mimick is an autonomous pentesting agent that chains 17 security tools with LLM reasoning to find real, exploitable vulnerabilities in web applications. It performs full-scope assessments — from subdomain enumeration to exploitation — and produces validated findings with reproduction steps.

[Getting Started](#getting-started) · [Usage](#usage) · [Tools](#tools) · [Benchmarks](#benchmarks) · [Architecture](#architecture)

</div>

---

## Features

- **Autonomous multi-phase methodology** — recon, discovery, misconfiguration audit, vulnerability hunting
- **17 integrated security tools** — nmap, sqlmap, nuclei, dalfox, ffuf, and more
- **Parallel child agents** — spawns focused sub-agents for subdomains with shared discovery
- **Auto-validation** — replays reproduction steps to independently confirm every finding
- **Adaptive strategy** — dynamic prompt injection based on discovered tech stack, WAF, and failed attacks
- **Attack graph tracking** — records every action as a directed graph for full audit trail
- **XBOW benchmark support** — run against 104 CTF challenges with automated scoring
- **Web dashboard** — visualize attack vectors and results

## Getting Started

### Prerequisites

- Python 3.12+
- Docker (for benchmarks)
- API key for an LLM provider (OpenRouter, OpenAI, or Anthropic)

### Install

```bash
git clone https://github.com/yourusername/mimick.git
cd mimick
pip install -e .
playwright install chromium
```

### External Tools

Mimick works best with these tools installed. It gracefully skips any that are missing.

```bash
# Core (recommended)
sudo apt install nmap curl

# ProjectDiscovery suite
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Scanners
go install github.com/ffuf/ffuf/v2@latest
pip install sqlmap arjun
go install github.com/hahwul/dalfox/v2@latest
pip install wafw00f
```

Check what's installed:

```bash
mimick tools
```

### Configuration

Set your LLM API key:

```bash
export OPENROUTER_API_KEY=sk-or-...
# or
export ANTHROPIC_API_KEY=sk-ant-...
# or
export OPENAI_API_KEY=sk-...
```

All settings can be configured via environment variables with the `MIMICK_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `MIMICK_MODEL` | `openrouter/anthropic/claude-sonnet-4-20250514` | LLM model identifier |
| `MIMICK_MAX_ITERATIONS` | `50` | Max agent iterations per scan |
| `MIMICK_OUTPUT_DIR` | `./results` | Directory for reports and attack graphs |
| `MIMICK_LOG_LEVEL` | `INFO` | Logging verbosity |

## Usage

### Scan a target

```bash
# Basic scan
mimick scan example.com

# Scoped scan with custom model
mimick scan https://app.example.com --scope "*.example.com" -m anthropic:claude-sonnet-4-20250514

# Focused scan
mimick scan https://api.example.com -p "Focus on SQL injection and IDOR"

# Parallel subdomain testing (10 concurrent child agents)
mimick scan example.com -c 10

# Custom output directory
mimick scan example.com -o ./results/acme-corp
```

### View results

```bash
# Launch the web dashboard
mimick web

# Serve results from a specific directory
mimick web -o ./results/acme-corp --port 3000
```

### Run benchmarks

```bash
# Run all 104 XBOW challenges
mimick benchmark /path/to/validation-benchmarks

# Filter by vulnerability type
mimick benchmark /path/to/validation-benchmarks --tags sqli,xss

# Easy challenges only, with 3 running in parallel
mimick benchmark /path/to/validation-benchmarks --level 1 -c 3

# Specific challenges
mimick benchmark /path/to/validation-benchmarks -f XBEN-001-24,XBEN-005-24
```

## Tools

| Tool | Type | Description |
|------|------|-------------|
| `subfinder` | Recon | Passive subdomain enumeration |
| `httpx` | Recon | HTTP probing — status codes, tech detection, titles |
| `nmap` | Recon | Port scanning and service detection |
| `wafw00f` | Recon | WAF identification |
| `katana` | Discovery | Web crawling and endpoint discovery |
| `ffuf` | Discovery | Directory and parameter fuzzing |
| `arjun` | Discovery | Hidden HTTP parameter discovery |
| `browser` | Discovery | Headless Chromium — JS rendering, library detection |
| `nuclei` | Scanning | Template-based vulnerability scanning |
| `sqlmap` | Exploitation | SQL injection detection and exploitation |
| `dalfox` | Exploitation | XSS scanning with WAF bypass |
| `interactsh` | Exploitation | Out-of-band interaction for blind vulns |
| `curl` | Utility | Raw HTTP requests |
| `python_exec` | Utility | Custom Python scripts for complex logic |
| `vuln_lookup` | Knowledge | Vulnerability cheatsheets and payloads |
| `report_finding` | Reporting | Register confirmed vulnerabilities |
| `spawn_agent` | Orchestration | Parallel child agents for subdomains |

## Benchmarks

Mimick includes a runner for the [XBOW validation benchmarks](https://github.com/xbow-org/xbow) — 104 Jeopardy-style CTF challenges covering 26 vulnerability classes across 3 difficulty levels.

```
mimick benchmark /path/to/validation-benchmarks --level 1

┌─────────────────────────────────────────────────────────────┐
│                    XBOW Benchmark Results                    │
├────┬──────────────┬───────┬───────────┬────────┬─────┬──────┤
│ #  │ Benchmark    │ Level │ Tags      │ Status │ Flag│ Time │
├────┼──────────────┼───────┼───────────┼────────┼─────┼──────┤
│ 1  │ XBEN-005-24  │   1   │ idor, jwt │ PASSED │  ✅ │  45s │
│ 2  │ XBEN-009-24  │   1   │ ssti      │ PASSED │  ✅ │  38s │
│ 3  │ XBEN-020-24  │   1   │ ssrf      │ PASSED │  ✅ │  52s │
│ ...│              │       │           │        │     │      │
└────┴──────────────┴───────┴───────────┴────────┴─────┴──────┘

Score: 32/45 (71%)
  Level 1: 32/45
  By tag:
    idor                      ████████░░ 8/10
    sqli                      ██████░░░░ 6/10
    xss                       █████░░░░░ 5/10
```

## Architecture

```
mimick scan example.com
         │
         ▼
┌─────────────────────────────────────────────┐
│              PydanticAI Agent               │
│                                             │
│  System Prompt (methodology + dynamic ctx)  │
│         │                                   │
│         ├─ Phase 1: Recon                   │
│         ├─ Phase 2: Discovery               │
│         ├─ Phase 3: Misconfiguration Audit  │
│         └─ Phase 4: Vulnerability Hunting   │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │         Tool Registry (17)          │    │
│  │  subfinder │ httpx │ nuclei │ ...   │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │      Adaptive Strategy Layer        │    │
│  │  • Tech stack detection             │    │
│  │  • Failure memory                   │    │
│  │  • Early termination                │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │      Child Agent Orchestration      │    │
│  │  • Shared discovery bus             │    │
│  │  • Focused task briefs              │    │
│  │  • Finding deduplication            │    │
│  └─────────────────────────────────────┘    │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│          Attack Graph Tracker        │
│  Records: tools → assets → findings  │
└──────────────────┬───────────────────┘
                   │
          ┌────────┼────────┐
          ▼        ▼        ▼
     .json      .md      validation
     graph    report      script
```

### Key Design Decisions

- **PydanticAI agent loop** — structured tool calling with streaming iteration
- **Dynamic prompt injection** — system prompt adapts each iteration based on discoveries, failures, and child agent findings
- **Finding deduplication** — normalized (URL, title) keys prevent duplicate reports across parent and child agents
- **Last-step validation** — multi-step reproduction flows (register → login → exploit) only judge the final step
- **Session propagation** — cookies from login steps automatically carry to exploit steps during validation

## Output

Each scan produces:

| File | Description |
|------|-------------|
| `results/mimick_<target>_<timestamp>.md` | Markdown report with findings, proof, and remediation |
| `results/<run_id>.json` | Full attack graph — nodes, edges, events timeline |
| `results/validation/<run_id>_validate.py` | Standalone script to re-verify all findings (stdlib only) |

## License

MIT
