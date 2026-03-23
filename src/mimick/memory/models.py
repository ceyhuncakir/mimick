from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field


class ChainStep(BaseModel):
    """A single tool call in an exploitation chain."""

    tool: str
    args: str
    result_summary: str


class Experience(BaseModel):
    """A validated finding with its full context for future retrieval.

    Three levels of abstraction (inspired by AgentRR):
      - strategy:    High-level lesson (injected into prompts)
      - observation:  Observation signature (embedded for semantic search)
      - chain:       Full tool-call chain (stored on disk for replay reference)
    """

    id: str = Field(default_factory=lambda: f"exp_{uuid4().hex[:12]}")

    # Level 1: Strategy — concise actionable lesson
    strategy: str

    # Level 2: Observation — what the agent saw (used for embedding search)
    observation: str

    # Finding metadata
    finding_title: str
    vuln_type: str
    severity: str  # critical, high, medium, low, info
    cvss: float | None = None
    tech_stack: list[str] = Field(default_factory=list)
    target_type: str = ""  # web_api, web_app, spa, etc.

    # Level 3: Full chain (stored in ChromaDB metadata as JSON string)
    chain: list[ChainStep] = Field(default_factory=list)

    # Cross-over linking (A-MEM inspired)
    related_ids: list[str] = Field(default_factory=list)

    # Validation status — updated after validation phase
    validated: bool = True

    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def searchable_document(self) -> str:
        """Text that gets embedded for semantic similarity search.

        Combines observation context with strategy for richer embeddings.
        """
        return f"{self.observation}\n\nStrategy: {self.strategy}"

    def metadata_dict(self) -> dict:
        """Flat metadata dict for ChromaDB storage."""
        return {
            "finding_title": self.finding_title,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "cvss": self.cvss or 0.0,
            "tech_stack": ",".join(self.tech_stack),
            "target_type": self.target_type,
            "validated": self.validated,
            "strategy": self.strategy,
            "observation": self.observation,
            "chain_json": self._chain_json(),
            "related_ids": ",".join(self.related_ids),
            "created_at": self.created_at,
        }

    def _chain_json(self) -> str:
        return json.dumps([step.model_dump() for step in self.chain])

    @classmethod
    def from_chroma_result(cls, id: str, document: str, metadata: dict) -> Experience:
        """Reconstruct an Experience from ChromaDB query results."""
        try:
            chain_data = json.loads(metadata.get("chain_json", "[]"))
        except (json.JSONDecodeError, TypeError):
            chain_data = []

        tech = metadata.get("tech_stack", "")
        related = metadata.get("related_ids", "")

        # Use the raw observation from metadata (not the combined document)
        observation = metadata.get("observation", "")
        if not observation:
            # Fallback for old entries that don't have observation in metadata:
            # strip the strategy suffix from the combined document
            observation = document.split("\n\nStrategy:")[0] if document else ""

        return cls(
            id=id,
            strategy=metadata.get("strategy", ""),
            observation=observation,
            finding_title=metadata.get("finding_title", ""),
            vuln_type=metadata.get("vuln_type", ""),
            severity=metadata.get("severity", ""),
            cvss=metadata.get("cvss") or None,
            tech_stack=tech.split(",") if tech else [],
            target_type=metadata.get("target_type", ""),
            chain=[ChainStep(**step) for step in chain_data],
            related_ids=related.split(",") if related else [],
            validated=metadata.get("validated", True),
            created_at=metadata.get("created_at", ""),
        )

    def format_for_prompt(self) -> str:
        """Format this experience for injection into the agent's system prompt."""
        chain_summary = " → ".join(
            f"{step.tool}({step.args[:60]})" for step in self.chain[:8]
        )
        lines = [
            f"### [{self.severity.upper()}] {self.finding_title}",
            f"**Strategy:** {self.strategy}",
            f"**Observation:** {self.observation[:200]}",
            f"**Chain:** {chain_summary}",
        ]
        if self.tech_stack:
            lines.append(f"**Tech:** {', '.join(self.tech_stack)}")
        if self.related_ids:
            lines.append(f"**Related experiences:** {len(self.related_ids)} linked")
        return "\n".join(lines)
