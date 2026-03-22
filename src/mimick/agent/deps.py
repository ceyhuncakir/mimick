from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from mimick.planner.planner import AttackPlanner
from mimick.tracker import AttackTracker

TOOL_ATTACK_TYPE: dict[str, str] = {
    "sqlmap": "sqli",
    "dalfox": "xss",
    "nuclei": "vuln_scan",
    "ffuf": "fuzzing",
    "arjun": "param_discovery",
    "nmap": "port_scan",
    "interactsh": "oob",
}

UNPRODUCTIVE_THRESHOLD: int = 5


@dataclass
class MimickDeps:
    target: str
    scope: str
    tracker: AttackTracker
    run_id: str
    is_child: bool = False
    concurrency: int = 5
    iteration: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)

    _semaphore: asyncio.Semaphore | None = field(default=None, repr=False)
    _child_tasks: list[asyncio.Task[Any]] = field(default_factory=list, repr=False)
    _parent_deps: MimickDeps | None = field(default=None, repr=False)
    _shared_child_findings: list[dict[str, Any]] = field(
        default_factory=list, repr=False
    )

    planner: AttackPlanner | None = field(default=None, repr=False)

    _attack_failures: dict[str, list[str]] = field(default_factory=dict, repr=False)

    _unproductive_streak: int = field(default=0, repr=False)
    _last_node_count: int = field(default=1, repr=False)

    _strategies_tried: dict[str, list[tuple[int, str]]] = field(
        default_factory=dict, repr=False
    )

    _auto_injected_lookups: set[str] = field(default_factory=set, repr=False)

    def get_semaphore(self) -> asyncio.Semaphore:
        if self._parent_deps:
            return self._parent_deps.get_semaphore()
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)
        return self._semaphore

    def record_attack_failure(self, tool_name: str, target_url: str) -> None:
        attack_type = TOOL_ATTACK_TYPE.get(tool_name)
        if attack_type:
            self._attack_failures.setdefault(attack_type, []).append(target_url)

    def get_failure_summary(self) -> dict[str, int]:
        return {k: len(v) for k, v in self._attack_failures.items() if len(v) >= 2}

    def update_productivity(self) -> None:
        current = self.tracker.node_count()
        if current == self._last_node_count:
            self._unproductive_streak += 1
        else:
            self._unproductive_streak = 0
        self._last_node_count = current

    def record_strategy(self, target_url: str, description: str) -> None:
        self._strategies_tried.setdefault(target_url, []).append(
            (self.iteration, description)
        )

    def get_stuck_targets(self, min_attempts: int = 3) -> dict[str, list[str]]:
        found_urls = {
            n.data.get("url", "") for n in self.tracker._nodes if n.type == "finding"
        }
        return {
            url: [s[1] for s in strategies]
            for url, strategies in self._strategies_tried.items()
            if url not in found_urls and len(strategies) >= min_attempts
        }
