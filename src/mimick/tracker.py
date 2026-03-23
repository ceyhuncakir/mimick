from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class GraphNode:
    id: str
    type: str
    label: str
    data: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    label: str = ""


class AttackTracker:
    """Records tool calls and discoveries as a directed attack graph."""

    def __init__(self, run_id: str, target: str, scope: str, prompt: str = "") -> None:
        self.run_id = run_id
        self.target = target
        self.scope = scope
        self.prompt = prompt
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.finished_at = ""
        self.status = "running"

        self._nodes: list[GraphNode] = []
        self._edges: list[GraphEdge] = []
        self._events: list[dict[str, Any]] = []
        self._node_ids: set[str] = set()
        self._action_seq = 0
        self._asset_seq = 0
        self._finding_seq = 0
        self._last_action_id: str | None = None
        self._finding_keys: set[str] = set()

        self._add_node(GraphNode("target", "target", target, {"scope": scope}))

    def _add_node(self, node: GraphNode) -> str:
        if node.id not in self._node_ids:
            self._nodes.append(node)
            self._node_ids.add(node.id)
        return node.id

    def _add_edge(self, source: str, target: str, label: str = "") -> None:
        self._edges.append(GraphEdge(source, target, label))

    def _make_asset_id(self, label: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9._:-]", "_", label)[:80]
        return f"asset_{safe}"

    def _make_finding_id(self) -> str:
        self._finding_seq += 1
        return f"finding_{self._finding_seq}"

    def record_reasoning(self, text: str, iteration: int) -> None:
        self._events.append(
            {
                "type": "reasoning",
                "iteration": iteration,
                "text": text[:2000],
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        )

    def record_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        stdout: str,
        stderr: str,
        success: bool,
        iteration: int,
    ) -> None:
        self._events.append(
            {
                "type": "tool_call",
                "tool": tool_name,
                "args": _sanitize_args(args),
                "stdout": stdout[:5000],
                "stderr": stderr[:2000] if stderr else "",
                "success": success,
                "iteration": iteration,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        )

        if tool_name == "vuln_lookup":
            return

        self._action_seq += 1
        action_id = f"action_{self._action_seq}_{tool_name}"

        self._add_node(
            GraphNode(
                id=action_id,
                type="tool",
                label=tool_name,
                data={
                    "args": _sanitize_args(args),
                    "stdout": stdout[:5000],
                    "stderr": stderr[:2000] if stderr else "",
                    "success": success,
                    "iteration": iteration,
                    "seq": self._action_seq,
                },
            )
        )

        parent = self._resolve_parent(tool_name, args)
        self._add_edge(parent, action_id, tool_name)

        if self._last_action_id and self._last_action_id != parent:
            self._add_edge(self._last_action_id, action_id, "then")

        self._last_action_id = action_id

        if success:
            self._extract(action_id, tool_name, args, stdout)

    def is_duplicate_finding(self, url: str, title: str) -> bool:
        norm_url = re.sub(r"https?://", "", url).rstrip("/").lower()
        norm_title = re.sub(
            r"^(reflected|stored|blind|dom[- ]based)\s+",
            "",
            title.lower().strip(),
        )
        key = f"{norm_url}||{norm_title}"
        if key in self._finding_keys:
            return True
        self._finding_keys.add(key)
        return False

    def record_finding(
        self,
        title: str,
        severity: str,
        url: str,
        description: str = "",
        proof: str = "",
        reproduction: list[dict] | None = None,
        impact: str = "",
        remediation: str = "",
        iteration: int = 0,
        vuln_type: str = "",
    ) -> None:
        fid = self._make_finding_id()
        self._add_node(
            GraphNode(
                fid,
                "finding",
                title,
                {
                    "severity": severity,
                    "url": url,
                    "description": description,
                    "proof": proof[:3000],
                    "reproduction": reproduction or [],
                    "impact": impact,
                    "remediation": remediation,
                    "iteration": iteration,
                    "vuln_type": vuln_type,
                },
            )
        )

        if self._last_action_id:
            self._add_edge(self._last_action_id, fid, severity)

        if url:
            asset_id = self._make_asset_id(url)
            if asset_id in self._node_ids:
                self._add_edge(asset_id, fid, "vulnerable")

        self._events.append(
            {
                "type": "finding",
                "title": title,
                "severity": severity,
                "url": url,
                "description": description,
                "proof": proof[:2000],
                "impact": impact,
                "iteration": iteration,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        )

    def finish(self, status: str = "completed") -> None:
        self.finished_at = datetime.now(timezone.utc).isoformat()
        self.status = status

    def to_dict(self) -> dict[str, Any]:
        stats = {"iterations": self._action_seq}
        type_counts: dict[str, int] = {}
        for n in self._nodes:
            type_counts[n.type] = type_counts.get(n.type, 0) + 1
        stats.update(type_counts)

        return {
            "id": self.run_id,
            "target": self.target,
            "scope": self.scope,
            "prompt": self.prompt,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "stats": stats,
            "nodes": [asdict(n) for n in self._nodes],
            "edges": [asdict(e) for e in self._edges],
            "events": self._events,
        }

    def save(self, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"{self.run_id}.json"
        path.write_text(json.dumps(self.to_dict(), indent=2))
        return path

    def _resolve_parent(self, tool_name: str, args: dict[str, Any]) -> str:
        target_val = (
            args.get("target")
            or args.get("host")
            or args.get("url")
            or args.get("domain")
        )
        if target_val:
            asset_id = self._make_asset_id(target_val)
            if asset_id in self._node_ids:
                return asset_id
        return "target"

    def _extract(self, action_id: str, tool_name: str, args: dict, stdout: str) -> None:
        extractors = {
            "subfinder": self._extract_subfinder,
            "httpx": self._extract_httpx,
            "nuclei": self._extract_nuclei,
            "katana": self._extract_katana,
            "ffuf": self._extract_ffuf,
            "nmap": self._extract_nmap,
            "wafw00f": self._extract_wafw00f,
            "curl": self._extract_curl,
            "arjun": self._extract_arjun,
            "sqlmap": self._extract_sqlmap,
            "dalfox": self._extract_dalfox,
        }
        fn = extractors.get(tool_name)
        if fn:
            fn(action_id, args, stdout)

    def _extract_subfinder(self, action_id: str, args: dict, stdout: str) -> None:
        hosts = [
            line.strip() for line in stdout.splitlines() if line.strip() and "." in line
        ]
        for host in hosts[:30]:
            nid = self._add_node(
                GraphNode(
                    self._make_asset_id(host),
                    "asset",
                    host,
                    {"kind": "subdomain"},
                )
            )
            self._add_edge(action_id, nid, "found")

    def _extract_httpx(self, action_id: str, args: dict, stdout: str) -> None:
        for line in stdout.splitlines()[:30]:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or obj.get("input")
            if not url:
                continue
            data: dict[str, Any] = {"kind": "host"}
            if obj.get("status_code"):
                data["status"] = obj["status_code"]
            if obj.get("title"):
                data["title"] = obj["title"]
            if obj.get("tech"):
                data["tech"] = obj["tech"]
            if obj.get("webserver"):
                data["server"] = obj["webserver"]
            nid = self._add_node(
                GraphNode(self._make_asset_id(url), "asset", url, data)
            )
            self._add_edge(action_id, nid, "probed")

    def _extract_nuclei(self, action_id: str, args: dict, stdout: str) -> None:
        for line in stdout.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info", {})
            severity = info.get("severity", "info")
            name = info.get("name") or obj.get("template-id", "unknown")
            matched = obj.get("matched-at", "")
            fid = self._make_finding_id()
            self._add_node(
                GraphNode(
                    fid,
                    "finding",
                    name,
                    {
                        "severity": severity,
                        "url": matched,
                        "template": obj.get("template-id", ""),
                    },
                )
            )
            self._add_edge(action_id, fid, severity)
            if matched:
                asset_id = self._make_asset_id(matched)
                if asset_id in self._node_ids:
                    self._add_edge(asset_id, fid, "vulnerable")

    def _extract_katana(self, action_id: str, args: dict, stdout: str) -> None:
        urls = [
            line.strip()
            for line in stdout.splitlines()
            if line.strip().startswith("http")
        ]
        for url in urls[:30]:
            nid = self._add_node(
                GraphNode(
                    self._make_asset_id(url),
                    "asset",
                    url,
                    {"kind": "endpoint"},
                )
            )
            self._add_edge(action_id, nid, "crawled")

    def _extract_ffuf(self, action_id: str, args: dict, stdout: str) -> None:
        for line in stdout.splitlines()[:30]:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url", "")
            if url:
                nid = self._add_node(
                    GraphNode(
                        self._make_asset_id(url),
                        "asset",
                        url,
                        {
                            "kind": "endpoint",
                            "status": obj.get("status", 0),
                            "length": obj.get("length", 0),
                        },
                    )
                )
                self._add_edge(action_id, nid, "fuzzed")

    def _extract_nmap(self, action_id: str, args: dict, stdout: str) -> None:
        for m in re.finditer(r"(\d+)/(\w+)\s+open\s+(\S+)", stdout):
            port, proto, service = m.groups()
            label = f"{args.get('target', '?')}:{port}/{service}"
            nid = self._add_node(
                GraphNode(
                    self._make_asset_id(label),
                    "asset",
                    label,
                    {
                        "kind": "port",
                        "port": int(port),
                        "proto": proto,
                        "service": service,
                    },
                )
            )
            self._add_edge(action_id, nid, "open")

    def _extract_wafw00f(self, action_id: str, args: dict, stdout: str) -> None:
        lower = stdout.lower()
        if "is behind" in lower:
            m = re.search(r"is behind\s+(.+?)(?:\s+WAF|\n|$)", stdout, re.IGNORECASE)
            waf_name = m.group(1).strip() if m else "Unknown WAF"
            nid = self._add_node(
                GraphNode(
                    self._make_asset_id(f"waf_{waf_name}"),
                    "asset",
                    f"WAF: {waf_name}",
                    {"kind": "waf", "waf": waf_name},
                )
            )
            self._add_edge(action_id, nid, "detected")

    def _extract_curl(self, action_id: str, args: dict, stdout: str) -> None:
        url = args.get("url", "")
        if url:
            nid = self._add_node(
                GraphNode(
                    self._make_asset_id(url),
                    "asset",
                    url,
                    {"kind": "endpoint"},
                )
            )
            self._add_edge(action_id, nid, "requested")

    def _extract_arjun(self, action_id: str, args: dict, stdout: str) -> None:
        try:
            obj = json.loads(stdout)
        except json.JSONDecodeError:
            return
        if isinstance(obj, dict):
            for url, data in obj.items():
                params = data.get("params", []) if isinstance(data, dict) else []
                if params:
                    label = f"{url} → {', '.join(params[:10])}"
                    nid = self._add_node(
                        GraphNode(
                            self._make_asset_id(url),
                            "asset",
                            label,
                            {"kind": "params", "url": url, "params": params},
                        )
                    )
                    self._add_edge(action_id, nid, "discovered")

    def _extract_sqlmap(self, action_id: str, args: dict, stdout: str) -> None:
        lower = stdout.lower()
        if "is vulnerable" in lower or "injectable" in lower:
            url = args.get("url", "?")
            param = args.get("param", "")
            title = f"SQL Injection: {param or 'param'} on {url}"
            fid = self._make_finding_id()
            self._add_node(
                GraphNode(
                    fid,
                    "finding",
                    title,
                    {
                        "severity": "high",
                        "url": url,
                        "tool": "sqlmap",
                    },
                )
            )
            self._add_edge(action_id, fid, "high")
            if url:
                asset_id = self._make_asset_id(url)
                if asset_id in self._node_ids:
                    self._add_edge(asset_id, fid, "vulnerable")

    def _extract_dalfox(self, action_id: str, args: dict, stdout: str) -> None:
        for line in stdout.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            xss_type = obj.get("type", "")
            poc = obj.get("poc", "") or obj.get("proof_of_concept", "")
            inject_url = obj.get("inject_url", "") or obj.get("url", "")
            if poc or "verified" in xss_type.lower():
                title = f"XSS ({xss_type})" if xss_type else "XSS"
                fid = self._make_finding_id()
                self._add_node(
                    GraphNode(
                        fid,
                        "finding",
                        title,
                        {
                            "severity": "medium",
                            "url": inject_url,
                            "poc": poc[:500],
                            "tool": "dalfox",
                        },
                    )
                )
                self._add_edge(action_id, fid, "medium")
                if inject_url:
                    asset_id = self._make_asset_id(inject_url)
                    if asset_id in self._node_ids:
                        self._add_edge(asset_id, fid, "vulnerable")

    def get_tech_summary(self) -> dict[str, list[str]]:
        tech_map: dict[str, list[str]] = {}
        for node in self._nodes:
            if node.type != "asset":
                continue
            tech = node.data.get("tech")
            server = node.data.get("server")
            if not tech and not server:
                continue
            items: list[str] = []
            if isinstance(tech, list):
                items.extend(tech)
            elif isinstance(tech, str):
                items.append(tech)
            if server:
                items.append(f"Server: {server}")
            if items:
                tech_map[node.label] = items
        return tech_map

    def get_waf_info(self) -> list[str]:
        return [
            node.data.get("waf", "Unknown")
            for node in self._nodes
            if node.type == "asset" and node.data.get("kind") == "waf"
        ]

    def get_discovered_endpoints(self) -> list[str]:
        return [
            node.label
            for node in self._nodes
            if node.type == "asset" and node.data.get("kind") in ("endpoint", "host")
        ]

    def get_findings_summary(self) -> list[dict[str, str]]:
        return [
            {
                "title": node.label,
                "severity": node.data.get("severity", ""),
                "url": node.data.get("url", ""),
            }
            for node in self._nodes
            if node.type == "finding"
        ]

    def get_discovered_params(self) -> dict[str, list[str]]:
        return {
            node.data["url"]: node.data.get("params", [])
            for node in self._nodes
            if node.type == "asset"
            and node.data.get("kind") == "params"
            and node.data.get("url")
        }

    def node_count(self) -> int:
        return len(self._nodes)


def _sanitize_args(args: dict) -> dict:
    clean = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > 500:
            clean[k] = v[:500] + "..."
        else:
            clean[k] = v
    return clean
