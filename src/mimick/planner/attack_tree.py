"""Attack tree implementation: a priority queue of pentesting task nodes."""

from __future__ import annotations

from typing import Any

from mimick.planner.models import (
    DEFAULT_PRIORITY,
    AttackNode,
    NodeStatus,
    Phase,
    TERMINAL_STATUSES,
)


class AttackTree:
    """Priority queue of attack nodes forming the pentesting plan."""

    def __init__(self) -> None:
        """Initialize an empty attack tree with no nodes or active task."""
        self._nodes: dict[str, AttackNode] = {}
        self._seq: int = 0
        self._active_node_id: str | None = None
        self._active_since_iteration: int = 0

    def create_node(
        self,
        phase: Phase,
        category: str,
        target_url: str,
        description: str,
        priority: int | None = None,
        depends_on: list[str] | None = None,
        hints: list[str] | None = None,
        max_retries: int = 2,
        iteration: int = 0,
    ) -> AttackNode:
        """Create a new attack node and add it to the tree.

        Args:
            phase: The pentesting phase this node belongs to.
            category: Short label for the attack category (e.g. ``"sqli"``).
            target_url: URL or host this node targets.
            description: Human-readable description of the task.
            priority: Scheduling priority (higher is sooner); defaults to DEFAULT_PRIORITY.
            depends_on: List of node IDs that must complete before this node.
            hints: Optional context hints for the agent.
            max_retries: Maximum number of retry attempts on failure.
            iteration: The iteration number when this node was created.

        Returns:
            The newly created AttackNode.
        """
        self._seq += 1
        node = AttackNode(
            id=f"{category}_{self._seq}",
            phase=phase,
            category=category,
            target_url=target_url,
            description=description,
            priority=priority if priority is not None else DEFAULT_PRIORITY,
            depends_on=depends_on or [],
            hints=hints or [],
            max_retries=max_retries,
            created_at_iteration=iteration,
        )
        self._nodes[node.id] = node
        return node

    def next_task(self, iteration: int = 0) -> AttackNode | None:
        """Return the next task to execute, activating it if necessary.

        Args:
            iteration: Current iteration number for timeout tracking.

        Returns:
            The active or highest-priority pending node, or None if none remain.
        """
        if self._active_node_id:
            active = self._nodes.get(self._active_node_id)
            if active and active.status == NodeStatus.ACTIVE:
                return active

        candidates = sorted(
            (
                n
                for n in self._nodes.values()
                if n.status == NodeStatus.PENDING and self._deps_met(n)
            ),
            key=lambda n: (n.phase.value, -n.priority),
        )
        if not candidates:
            return None

        best = candidates[0]
        best.status = NodeStatus.ACTIVE
        self._active_node_id = best.id
        self._active_since_iteration = iteration
        return best

    def get_active_task(self) -> AttackNode | None:
        """Return the currently active task, or None if no task is active."""
        if self._active_node_id:
            node = self._nodes.get(self._active_node_id)
            if node and node.status == NodeStatus.ACTIVE:
                return node
        return None

    def complete_task(self, node_id: str, result: str = "") -> None:
        """Mark a task as completed and store its result summary.

        Args:
            node_id: Identifier of the node to complete.
            result: Optional result summary (truncated to 500 chars).
        """
        node = self._nodes.get(node_id)
        if not node:
            return
        node.status = NodeStatus.COMPLETED
        node.result_summary = result[:500]
        if self._active_node_id == node_id:
            self._active_node_id = None

    def fail_task(self, node_id: str, result: str = "") -> None:
        """Mark a task as failed, retrying if attempts remain.

        Args:
            node_id: Identifier of the node that failed.
            result: Optional failure description (truncated for storage).
        """
        node = self._nodes.get(node_id)
        if not node:
            return
        node.retry_count += 1
        if node.can_retry:
            node.status = NodeStatus.PENDING
            node.hints.append(f"Previous attempt failed: {result[:200]}")
            node.priority = min(node.priority + 5, 100)
        else:
            node.status = NodeStatus.FAILED
            node.result_summary = result[:500]
        if self._active_node_id == node_id:
            self._active_node_id = None

    def skip_task(self, node_id: str, reason: str = "") -> None:
        """Mark a task as skipped.

        Args:
            node_id: Identifier of the node to skip.
            reason: Optional reason for skipping (truncated to 200 chars).
        """
        node = self._nodes.get(node_id)
        if not node:
            return
        node.status = NodeStatus.SKIPPED
        node.result_summary = reason[:200]
        if self._active_node_id == node_id:
            self._active_node_id = None

    def check_task_timeout(self, current_iteration: int, budget: int = 5) -> bool:
        """Auto-complete the active task if it has exceeded its iteration budget.

        Args:
            current_iteration: The current iteration number.
            budget: Maximum iterations a task may stay active.

        Returns:
            True if the active task was timed out and auto-completed.
        """
        active = self.get_active_task()
        if not active:
            return False
        if current_iteration - self._active_since_iteration >= budget:
            self.complete_task(active.id, "Auto-completed (iteration budget exhausted)")
            return True
        return False

    def has_node_for(self, category: str, target_url: str) -> bool:
        """Return whether a node with the given category and target already exists."""
        return any(
            n.category == category and n.target_url == target_url
            for n in self._nodes.values()
        )

    def coverage_summary(self) -> dict[str, Any]:
        """Return a summary of task coverage grouped by status and phase."""
        by_status: dict[str, int] = {}
        by_phase: dict[str, dict[str, int]] = {}

        for node in self._nodes.values():
            by_status[node.status.value] = by_status.get(node.status.value, 0) + 1
            pname = node.phase.name.lower()
            phase_stats = by_phase.setdefault(
                pname, {"total": 0, "completed": 0, "pending": 0, "failed": 0}
            )
            phase_stats["total"] += 1
            if node.status == NodeStatus.COMPLETED:
                phase_stats["completed"] += 1
            elif node.status in (NodeStatus.PENDING, NodeStatus.ACTIVE):
                phase_stats["pending"] += 1
            elif node.status == NodeStatus.FAILED:
                phase_stats["failed"] += 1

        done = by_status.get("completed", 0) + by_status.get("skipped", 0)
        total = len(self._nodes)
        return {
            "total_tasks": total,
            "by_status": by_status,
            "by_phase": by_phase,
            "completion_pct": round(done / max(total, 1) * 100),
        }

    def pending_tasks_summary(self, limit: int = 5) -> list[dict[str, str]]:
        """Return a list of the top pending tasks sorted by phase and priority.

        Args:
            limit: Maximum number of tasks to return.

        Returns:
            List of dicts with category, target, description, and priority keys.
        """
        pending = sorted(
            (
                n
                for n in self._nodes.values()
                if n.status == NodeStatus.PENDING and self._deps_met(n)
            ),
            key=lambda n: (n.phase.value, -n.priority),
        )
        return [
            {
                "category": n.category,
                "target": n.target_url,
                "description": n.description[:100],
                "priority": str(n.priority),
            }
            for n in pending[:limit]
        ]

    def _deps_met(self, node: AttackNode) -> bool:
        """Return whether all dependencies of the node have reached a terminal status."""
        return all(
            (dep := self._nodes.get(dep_id)) is None or dep.status in TERMINAL_STATUSES
            for dep_id in node.depends_on
        )
