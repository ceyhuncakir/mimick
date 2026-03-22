from __future__ import annotations

from urllib.parse import urlparse

from mimick.planner.attack_tree import AttackTree
from mimick.planner.models import AttackNode, NodeStatus, Phase
from mimick.planner.search_tree import SearchTree
from mimick.tracker import AttackTracker

_SEARCH_TREE_PHASES: frozenset[Phase] = frozenset(
    {Phase.VULN_HUNT, Phase.EXPLOIT, Phase.ESCALATE}
)


class AttackPlanner:
    """Manage the attack tree as an agent-driven priority queue."""

    def __init__(self, target: str, scope: str) -> None:
        self.target = target
        self.scope = scope
        self.tree = AttackTree()

        self._processed_event_count: int = 0
        self._tech_stack: set[str] = set()
        self._waf_detected: bool = False

        self._search_trees: dict[str, SearchTree] = {}

        self._build_initial_tree()

    def _build_initial_tree(self) -> None:
        t = self.tree
        is_single = self._is_single_url()

        if not is_single:
            parsed = urlparse(self.target)
            sub = t.create_node(
                Phase.RECON,
                "subdomain_enum",
                parsed.netloc or self.target,
                f"Enumerate subdomains of {parsed.netloc}",
                priority=50,
            )
            t.create_node(
                Phase.RECON,
                "http_probe",
                self.target,
                "Probe discovered hosts for live services and tech stack",
                priority=50,
                depends_on=[sub.id],
            )
            t.create_node(
                Phase.RECON,
                "port_scan",
                self.target,
                "Scan high-value hosts for web ports",
                priority=35,
            )

        t.create_node(
            Phase.RECON,
            "waf_detect",
            self.target,
            "Detect WAF protecting the target",
            priority=45,
        )
        t.create_node(
            Phase.DISCOVERY,
            "browser_render",
            self.target,
            "Render in browser — detect frameworks, forms, links, cookies",
            priority=60,
        )
        t.create_node(
            Phase.DISCOVERY,
            "crawl",
            self.target,
            "Crawl to discover endpoints, JS files, API routes",
            priority=55,
        )
        t.create_node(
            Phase.DISCOVERY,
            "endpoint_discovery",
            self.target,
            "Fuzz and discover hidden directories, files, and parameters",
            priority=50,
        )
        t.create_node(
            Phase.MISCONFIG,
            "security_audit",
            self.target,
            "Audit security headers, cookie flags, CORS, HTTPS, config exposure",
            priority=30,
            max_retries=0,
        )

    def _is_single_url(self) -> bool:
        parsed = urlparse(self.target)
        hostname = parsed.hostname or ""
        return (
            bool(parsed.path and parsed.path != "/")
            or hostname in ("localhost", "127.0.0.1", "0.0.0.0")
            or (parsed.port is not None and parsed.port not in (80, 443))
        )

    def next_task(self, iteration: int = 0) -> AttackNode | None:
        return self.tree.next_task(iteration)

    def create_task(
        self,
        category: str,
        target_url: str,
        description: str,
        priority: int,
        phase: str = "vuln_hunt",
        hints: list[str] | None = None,
        iteration: int = 0,
    ) -> AttackNode | None:
        phase_map: dict[str, Phase] = {
            "recon": Phase.RECON,
            "discovery": Phase.DISCOVERY,
            "misconfig": Phase.MISCONFIG,
            "vuln_hunt": Phase.VULN_HUNT,
            "exploit": Phase.EXPLOIT,
            "escalate": Phase.ESCALATE,
        }
        phase_enum = phase_map.get(phase.lower(), Phase.VULN_HUNT)

        if self.tree.has_node_for(category, target_url):
            for node in self.tree._nodes.values():
                if (
                    node.category == category
                    and node.target_url == target_url
                    and node.status == NodeStatus.PENDING
                    and priority > node.priority
                ):
                    node.priority = min(priority, 100)
                    if hints:
                        node.hints.extend(hints)
                    return node
            return None

        return self.tree.create_node(
            phase=phase_enum,
            category=category,
            target_url=target_url,
            description=description,
            priority=min(priority, 100),
            hints=hints or [],
            iteration=iteration,
        )

    def complete_current(self, result: str = "") -> None:
        active = self.tree.get_active_task()
        if not active:
            return
        stree = self._search_trees.get(active.id)
        if stree:
            approach = stree.get_active()
            if approach:
                stree.record_result(approach.id, succeeded=True, reflection=result)
        self.tree.complete_task(active.id, result)

    def fail_current(self, result: str = "") -> bool:
        active = self.tree.get_active_task()
        if not active:
            return False

        stree = self._search_trees.get(active.id)
        if stree:
            current = stree.get_active()
            if current:
                stree.record_result(current.id, succeeded=False, reflection=result)
            if not stree.all_exhausted() and stree.select():
                return True

        self.tree.fail_task(active.id, result)
        return False

    def get_active_search_tree(self) -> SearchTree | None:
        active = self.tree.get_active_task()
        return self._search_trees.get(active.id) if active else None

    def skip_current(self, reason: str = "") -> None:
        active = self.tree.get_active_task()
        if active:
            self.tree.skip_task(active.id, reason)

    def get_or_create_search_tree(self, node: AttackNode) -> SearchTree | None:
        if node.phase not in _SEARCH_TREE_PHASES:
            return None
        if node.id in self._search_trees:
            return self._search_trees[node.id]

        stree = SearchTree(
            node_id=node.id,
            category=node.category,
            target_url=node.target_url,
            tech_hints=self._tech_stack,
            waf_detected=self._waf_detected,
        )
        stree.select()
        self._search_trees[node.id] = stree
        return stree

    def perceive(self, tracker: AttackTracker, iteration: int) -> None:
        self._process_completions(tracker)
        self._update_tech_and_waf(tracker)

        active = self.tree.get_active_task()
        budget = 8 if (active and active.id in self._search_trees) else 5
        self.tree.check_task_timeout(iteration, budget=budget)

    def _process_completions(self, tracker: AttackTracker) -> None:
        events = tracker._events[self._processed_event_count :]
        self._processed_event_count = len(tracker._events)

        active = self.tree.get_active_task()
        if not active:
            return

        for event in events:
            if event.get("type") == "tool_call" and event.get("success"):
                if active.phase in (Phase.RECON, Phase.DISCOVERY):
                    self.tree.complete_task(
                        active.id, f"{event.get('tool', '')} completed"
                    )
                    return

            if event.get("type") == "finding":
                finding_url = event.get("url", "")
                if (
                    active.phase in _SEARCH_TREE_PHASES
                    and finding_url
                    and (
                        finding_url in active.target_url
                        or active.target_url in finding_url
                    )
                ):
                    self.tree.complete_task(
                        active.id, f"Finding: {event.get('title', '')}"
                    )
                    return

    def _update_tech_and_waf(self, tracker: AttackTracker) -> None:
        for techs in tracker.get_tech_summary().values():
            self._tech_stack.update(t.lower() for t in techs)
        if not self._waf_detected and tracker.get_waf_info():
            self._waf_detected = True

    def build_directive(self, iteration: int = 0) -> str:
        active = self.tree.get_active_task() or self.next_task(iteration)
        if not active:
            return ""

        self.get_or_create_search_tree(active)
        coverage = self.tree.coverage_summary()
        pending = self.tree.pending_tasks_summary(limit=4)

        lines = [
            "# Current Objective (from attack planner)",
            "",
            f"**Priority task**: {active.description}",
            f"**Target**: `{active.target_url}`",
            f"**Category**: {active.category} | **Phase**: {active.phase.name}",
        ]

        if active.hints:
            lines.append(f"**Hints**: {'; '.join(active.hints[-3:])}")
        if active.retry_count > 0:
            lines.append(
                f"**Retry #{active.retry_count}**: Previous attempt failed — "
                "escalate technique or try a different approach."
            )

        stree = self._search_trees.get(active.id)
        if stree:
            ctx = stree.build_context()
            if ctx:
                lines += ["", ctx]

        lines += [
            "",
            f"## Plan Progress ({coverage['completion_pct']}%% complete, "
            f"{coverage['total_tasks']} tasks)",
        ]
        for phase_name, stats in coverage["by_phase"].items():
            done, total = stats["completed"], stats["total"]
            pct = round(done / max(total, 1) * 100)
            marker = (
                "done"
                if pct == 100
                else ("active" if stats["pending"] > 0 else "stuck")
            )
            lines.append(f"- [{marker}] **{phase_name}**: {done}/{total} ({pct}%%)")

        if pending:
            lines += ["", "## Next in Queue"]
            lines += [
                f"- [{t['category']}] {t['description']}"
                for t in pending
                if t["category"] != active.category or t["target"] != active.target_url
            ]

        lines += [
            "",
            "Execute the priority task. Call `plan_next(status='completed')` when "
            "done, or `plan_next(status='failed', note='...')` to backtrack. "
            "Use `create_task(...)` to add new tasks when you discover attack vectors.",
        ]
        return "\n".join(lines)
