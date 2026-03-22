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
        self.node_id = node_id
        self.category = category
        self.target_url = target_url
        self._approaches: list[Approach] = self._generate(
            tech_hints or set(), waf_detected
        )
        self._active_id: str | None = None

    def _generate(self, tech_hints: set[str], waf_detected: bool) -> list[Approach]:
        templates = APPROACH_CATALOG.get(self.category, FALLBACK_APPROACHES)
        approaches = [t.instantiate(tech_hints) for t in templates]
        if waf_detected:
            for a in approaches:
                a.payload_hint += " [WAF detected — use encoding/tamper]"
        return approaches

    def select(self) -> Approach | None:
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
        return self._find(self._active_id) if self._active_id else None

    def all_exhausted(self) -> bool:
        return all(a.is_terminal for a in self._approaches)

    def remaining_count(self) -> int:
        return sum(1 for a in self._approaches if not a.is_terminal)

    def build_context(self) -> str:
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
        if not approach_id:
            return None
        return next((a for a in self._approaches if a.id == approach_id), None)
