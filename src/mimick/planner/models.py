from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


class Phase(Enum):
    RECON = 1
    DISCOVERY = 2
    MISCONFIG = 3
    VULN_HUNT = 4
    EXPLOIT = 5
    ESCALATE = 6


class NodeStatus(Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ApproachStatus(Enum):
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
        return self.retry_count < self.max_retries

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES


@dataclass
class Approach:
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
        return self.status in (ApproachStatus.SUCCEEDED, ApproachStatus.FAILED)


@dataclass
class ApproachTemplate:
    desc: str
    tools: list[str]
    payload: str = ""
    tech_variants: dict[str, str] = field(default_factory=dict)

    def instantiate(self, tech_hints: set[str]) -> Approach:
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
