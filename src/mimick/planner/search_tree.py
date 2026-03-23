"""Search tree for UCB1-guided approach exploration on attack-tree tasks."""

from __future__ import annotations

import math

from mimick.planner.catalog import APPROACH_CATALOG, FALLBACK_APPROACHES
from mimick.planner.models import Approach, ApproachStatus, UCB1_C


class SearchTree:
    """Manage approach exploration for a single attack-tree task using UCB1."""

    def __init__(
        self,
        node_id: str,
        category: str,
        target_url: str,
        tech_hints: set[str] | None = None,
        waf_detected: bool = False,
    ) -> None:
        """Initialize the search tree and generate approaches from the catalog.

        Args:
            node_id: Identifier of the parent attack-tree node.
            category: Attack category used to look up approach templates.
            target_url: URL this search tree targets.
            tech_hints: Detected technologies for tailoring payloads.
            waf_detected: Whether a WAF has been detected on the target.
        """
        self.node_id = node_id
        self.category = category
        self.target_url = target_url
        self._approaches: list[Approach] = self._generate(
            tech_hints or set(), waf_detected
        )
        self._active_id: str | None = None

    def _generate(self, tech_hints: set[str], waf_detected: bool) -> list[Approach]:
        """Generate concrete approaches from catalog templates.

        Args:
            tech_hints: Detected technologies for variant selection.
            waf_detected: Whether to append WAF evasion hints.

        Returns:
            List of instantiated Approach objects.
        """
        templates = APPROACH_CATALOG.get(self.category, FALLBACK_APPROACHES)
        approaches = [t.instantiate(tech_hints) for t in templates]
        if waf_detected:
            for a in approaches:
                a.payload_hint += " [WAF detected — use encoding/tamper]"
        return approaches

    def select(self) -> Approach | None:
        """Select the next untried approach using UCB1 and mark it active.

        Returns:
            The selected Approach, or None if all approaches have been tried.
        """
        candidates = [a for a in self._approaches if a.status == ApproachStatus.UNTRIED]
        if not candidates:
            return None

        total_visits = max(sum(a.visits for a in self._approaches), 1)

        def _ucb1(a: Approach) -> float:
            if a.visits == 0:
                return float("inf")
            exploitation = a.reward / a.visits
            exploration = UCB1_C * math.sqrt(math.log(total_visits) / a.visits)
            return exploitation + exploration

        best = max(candidates, key=_ucb1)
        best.status = ApproachStatus.ACTIVE
        self._active_id = best.id
        return best

    def record_result(
        self, approach_id: str, *, succeeded: bool, reflection: str = ""
    ) -> None:
        """Record the outcome of an approach attempt.

        Args:
            approach_id: Identifier of the approach to update.
            succeeded: Whether the approach succeeded.
            reflection: Optional reflection on the outcome (truncated to 300 chars).
        """
        approach = self._find(approach_id)
        if not approach:
            return

        approach.visits += 1
        approach.reward += 1.0 if succeeded else 0.0
        approach.reflection = reflection[:300]
        approach.status = (
            ApproachStatus.SUCCEEDED if succeeded else ApproachStatus.FAILED
        )

        if self._active_id == approach_id:
            self._active_id = None

    def get_active(self) -> Approach | None:
        """Return the currently active approach, or None."""
        return self._find(self._active_id) if self._active_id else None

    def all_exhausted(self) -> bool:
        """Return whether every approach has reached a terminal status."""
        return all(a.is_terminal for a in self._approaches)

    def remaining_count(self) -> int:
        """Return the number of approaches that have not yet reached a terminal status."""
        return sum(1 for a in self._approaches if not a.is_terminal)

    def build_context(self) -> str:
        """Build a markdown context block describing the current approach strategy.

        Returns:
            Formatted markdown string, or empty string if no approaches remain.
        """
        active = self.get_active() or self.select()
        if not active:
            return ""

        total = len(self._approaches)
        tried = sum(1 for a in self._approaches if a.is_terminal)
        remaining = total - tried - 1

        lines = [
            "## Approach Strategy (LATS Search)",
            "",
            f"**Try now** ({tried + 1}/{total}): {active.description}",
            f"- **Tools**: {', '.join(active.tools_hint)}",
        ]
        if active.payload_hint:
            lines.append(f"- **Technique**: {active.payload_hint}")
        if remaining > 0:
            lines.append(f"- **Remaining alternatives**: {remaining}")

        failed_with_reflections = [
            a
            for a in self._approaches
            if a.status == ApproachStatus.FAILED and a.reflection
        ]
        if failed_with_reflections:
            lines += ["", "### Learned from failed approaches:"]
            for i, a in enumerate(failed_with_reflections[-3:], 1):
                lines.append(f"{i}. **{a.description}** — FAILED")
                lines.append(f'   Reflection: "{a.reflection}"')

        lines += [
            "",
            "When this approach fails, call `plan_next(status='failed', "
            "note='<explain why>')` so the search can backtrack to the next approach.",
        ]
        return "\n".join(lines)

    def _find(self, approach_id: str | None) -> Approach | None:
        """Look up an approach by ID.

        Args:
            approach_id: The approach identifier, or None.

        Returns:
            The matching Approach, or None if not found.
        """
        if not approach_id:
            return None
        return next((a for a in self._approaches if a.id == approach_id), None)
