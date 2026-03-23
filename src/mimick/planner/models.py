"""Domain models for the attack planner: phases, statuses, and node dataclasses."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


class Phase(Enum):
    """Represent the sequential phases of a penetration test."""

    RECON = 1
    DISCOVERY = 2
    MISCONFIG = 3
    VULN_HUNT = 4
    EXPLOIT = 5
    ESCALATE = 6


class NodeStatus(Enum):
    """Track the lifecycle status of an attack node."""

    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ApproachStatus(Enum):
    """Track the lifecycle status of an approach within a search tree."""

    UNTRIED = "untried"
    ACTIVE = "active"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


DEFAULT_PRIORITY: int = 50

UCB1_C: float = 1.41

TERMINAL_STATUSES: frozenset[NodeStatus] = frozenset(
    {NodeStatus.COMPLETED, NodeStatus.FAILED, NodeStatus.SKIPPED}
)


@dataclass
class AttackNode:
    """Represent a single task node in the attack tree."""

    id: str
    phase: Phase
    category: str
    target_url: str
    description: str
    priority: int
    status: NodeStatus = NodeStatus.PENDING
    retry_count: int = 0
    max_retries: int = 2
    depends_on: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    result_summary: str = ""
    created_at_iteration: int = 0

    @property
    def can_retry(self) -> bool:
        """Return whether the node has remaining retry attempts."""
        return self.retry_count < self.max_retries

    @property
    def is_terminal(self) -> bool:
        """Return whether the node has reached a terminal status."""
        return self.status in TERMINAL_STATUSES


@dataclass
class Approach:
    """Represent a single exploration approach within a search tree."""

    id: str
    description: str
    tools_hint: list[str]
    payload_hint: str = ""
    status: ApproachStatus = ApproachStatus.UNTRIED
    visits: int = 0
    reward: float = 0.0
    reflection: str = ""

    @property
    def is_terminal(self) -> bool:
        """Return whether the approach has reached a terminal status."""
        return self.status in (ApproachStatus.SUCCEEDED, ApproachStatus.FAILED)


@dataclass
class ApproachTemplate:
    """Define a reusable template for instantiating concrete approaches."""

    desc: str
    tools: list[str]
    payload: str = ""
    tech_variants: dict[str, str] = field(default_factory=dict)

    def instantiate(self, tech_hints: set[str]) -> Approach:
        """Create a concrete Approach, injecting technology-specific hints.

        Args:
            tech_hints: Set of detected technology names to match against variants.

        Returns:
            A new Approach instance with tech-specific payload hints applied.
        """
        extra = next(
            (
                f" [{k.upper()} hint: {v}]"
                for k, v in self.tech_variants.items()
                if k in tech_hints
            ),
            "",
        )
        payload = f"{self.payload}{extra}" if self.payload else extra.strip()

        return Approach(
            id=f"a_{uuid.uuid4().hex[:8]}",
            description=self.desc,
            tools_hint=list(self.tools),
            payload_hint=payload,
        )
