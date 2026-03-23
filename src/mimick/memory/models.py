"""Data models for the experience memory system."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ChainStep(BaseModel):
    """A single tool call in an exploitation chain.

    Attributes:
        tool: Name of the tool that was invoked.
        args: Serialized argument string passed to the tool.
        result_summary: Compact summary of the tool's output.
    """

    tool: str
    args: str
    result_summary: str


class Experience(BaseModel):
    """A validated finding with its full context for future retrieval.

    Stores three levels of abstraction:
        - strategy: High-level actionable lesson injected into prompts.
        - observation: Observation signature embedded for semantic search.
        - chain: Full tool-call chain stored on disk for replay reference.

    Attributes:
        id: Unique identifier for this experience.
        strategy: Concise actionable lesson derived from the finding.
        observation: What the agent observed leading up to the finding.
        finding_title: Short title describing the vulnerability found.
        vuln_type: Category of vulnerability (e.g. "xss", "sqli").
        severity: Severity level (critical, high, medium, low, info).
        cvss: Optional CVSS score.
        tech_stack: Technologies detected on the target.
        target_type: Classification of the target (web_api, web_app, spa).
        chain: Ordered list of tool calls that led to the finding.
        related_ids: IDs of experiences linked via cross-over discovery.
        validated: Whether the finding has been confirmed.
        created_at: ISO 8601 timestamp of when the experience was created.
    """

    id: str = Field(default_factory=lambda: f"exp_{uuid4().hex[:12]}")
    strategy: str
    observation: str
    finding_title: str
    vuln_type: str
    severity: str
    cvss: float | None = None
    tech_stack: list[str] = Field(default_factory=list)
    target_type: str = ""
    chain: list[ChainStep] = Field(default_factory=list)
    related_ids: list[str] = Field(default_factory=list)
    validated: bool = True
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def searchable_document(self) -> str:
        """Build the text that gets embedded for semantic similarity search.

        Returns:
            Combined observation and strategy text.
        """
        return f"{self.observation}\n\nStrategy: {self.strategy}"

    def metadata_dict(self) -> dict[str, Any]:
        """Serialize to a flat metadata dict suitable for ChromaDB storage.

        Returns:
            Dictionary with string/numeric values for all fields.
        """
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
        """Serialize the chain to a JSON string.

        Returns:
            JSON array of chain step dictionaries.
        """
        return json.dumps([step.model_dump() for step in self.chain])

    @classmethod
    def from_chroma_result(
        cls, id: str, document: str, metadata: dict[str, Any]
    ) -> Experience:
        """Reconstruct an Experience from ChromaDB query results.

        Args:
            id: The experience ID stored in ChromaDB.
            document: The embedded document text.
            metadata: Flat metadata dictionary from ChromaDB.

        Returns:
            Reconstructed Experience instance.
        """
        try:
            chain_data: list[dict[str, str]] = json.loads(
                metadata.get("chain_json", "[]")
            )
        except (json.JSONDecodeError, TypeError):
            chain_data = []

        tech: str = metadata.get("tech_stack", "")
        related: str = metadata.get("related_ids", "")

        observation: str = metadata.get("observation", "")
        if not observation:
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
        """Format this experience for injection into the agent's system prompt.

        Returns:
            Markdown-formatted string summarizing the experience.
        """
        chain_summary: str = " → ".join(
            f"{step.tool}({step.args[:60]})" for step in self.chain[:8]
        )
        lines: list[str] = [
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
