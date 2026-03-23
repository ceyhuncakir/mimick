"""Persistent experience store backed by ChromaDB."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import chromadb

from mimick.config import settings
from mimick.logger import get_logger
from mimick.memory.models import Experience

log = get_logger("experience")


class ExperienceStore:
    """Persistent experience memory with semantic search over observation contexts.

    Uses ChromaDB's built-in all-MiniLM-L6-v2 embeddings for local
    similarity search without an external API.

    Attributes:
        _client: ChromaDB persistent client instance.
        _collection: ChromaDB collection holding experience documents.
    """

    def __init__(self, db_dir: Path) -> None:
        """Initialize the store, creating the database directory if needed.

        Args:
            db_dir: Filesystem path for the ChromaDB persistent storage.
        """
        db_dir.mkdir(parents=True, exist_ok=True)
        self._client: chromadb.PersistentClient = chromadb.PersistentClient(
            path=str(db_dir)
        )
        self._collection: chromadb.Collection = self._client.get_or_create_collection(
            name=settings.experience_collection,
            metadata={"hnsw:space": "cosine"},
        )
        log.info(
            "Experience store loaded: %d experiences from %s",
            self._collection.count(),
            db_dir,
        )

    def add(self, experience: Experience) -> None:
        """Store a new experience, upserting by ID.

        Args:
            experience: The experience to persist.
        """
        self._collection.upsert(
            ids=[experience.id],
            documents=[experience.searchable_document()],
            metadatas=[experience.metadata_dict()],
        )
        log.info(
            "Stored experience %s: [%s] %s",
            experience.id,
            experience.severity,
            experience.finding_title,
        )

    def query(
        self,
        observation: str,
        top_k: int = 2,
        vuln_type: str | None = None,
        min_severity: str | None = None,
    ) -> list[Experience]:
        """Retrieve similar past experiences by observation context.

        Args:
            observation: Current observation text to match against.
            top_k: Maximum number of results to return.
            vuln_type: Optional filter to restrict results to a specific
                vulnerability type.
            min_severity: Optional minimum severity threshold. Results at
                or above this level are returned.

        Returns:
            List of matching experiences ordered by similarity.
        """
        if self._collection.count() == 0:
            return []

        where: dict[str, Any] | None = None
        conditions: list[dict[str, Any]] = [{"validated": True}]

        if vuln_type:
            conditions.append({"vuln_type": vuln_type})

        if min_severity:
            severity_order: list[str] = [
                "info",
                "low",
                "medium",
                "high",
                "critical",
            ]
            idx: int = (
                severity_order.index(min_severity)
                if min_severity in severity_order
                else 0
            )
            if idx > 0:
                conditions.append({"severity": {"$in": severity_order[idx:]}})

        if len(conditions) == 1:
            where = conditions[0]
        elif len(conditions) > 1:
            where = {"$and": conditions}

        try:
            results: dict[str, Any] = self._collection.query(
                query_texts=[observation],
                n_results=min(top_k, self._collection.count()),
                where=where,
                include=["documents", "metadatas", "distances"],
            )
        except Exception:
            results = self._collection.query(
                query_texts=[observation],
                n_results=min(top_k, self._collection.count()),
                include=["documents", "metadatas", "distances"],
            )

        experiences: list[Experience] = []
        if not results["ids"] or not results["ids"][0]:
            return experiences

        for i, exp_id in enumerate(results["ids"][0]):
            doc: str = results["documents"][0][i] if results["documents"] else ""
            meta: dict[str, Any] = (
                results["metadatas"][0][i] if results["metadatas"] else {}
            )
            distance: float = (
                results["distances"][0][i] if results["distances"] else 1.0
            )

            if distance > 0.7:
                continue

            exp: Experience = Experience.from_chroma_result(exp_id, doc, meta)
            experiences.append(exp)

        return experiences

    def get(self, experience_id: str) -> Experience | None:
        """Fetch a specific experience by its ID.

        Args:
            experience_id: Unique identifier of the experience.

        Returns:
            The matching experience, or ``None`` if not found.
        """
        result: dict[str, Any] = self._collection.get(
            ids=[experience_id],
            include=["documents", "metadatas"],
        )
        if not result["ids"]:
            return None
        return Experience.from_chroma_result(
            result["ids"][0],
            result["documents"][0] if result["documents"] else "",
            result["metadatas"][0] if result["metadatas"] else {},
        )

    def link(self, exp_id_a: str, exp_id_b: str) -> None:
        """Create a bidirectional link between two experiences.

        Args:
            exp_id_a: ID of the first experience.
            exp_id_b: ID of the second experience.
        """
        a: Experience | None = self.get(exp_id_a)
        b: Experience | None = self.get(exp_id_b)
        if not a or not b:
            return

        if exp_id_b not in a.related_ids:
            a.related_ids.append(exp_id_b)
            self._collection.update(
                ids=[exp_id_a],
                metadatas=[a.metadata_dict()],
            )

        if exp_id_a not in b.related_ids:
            b.related_ids.append(exp_id_a)
            self._collection.update(
                ids=[exp_id_b],
                metadatas=[b.metadata_dict()],
            )

        log.debug("Linked experiences: %s <-> %s", exp_id_a, exp_id_b)

    def find_related(self, experience: Experience, top_k: int = 3) -> list[Experience]:
        """Find experiences related to the given one for auto-linking.

        Queries by the same observation to find similar chains, then
        filters out the experience itself.

        Args:
            experience: The reference experience to find relatives for.
            top_k: Maximum number of related experiences to return.

        Returns:
            List of related experiences, excluding the input experience.
        """
        candidates: list[Experience] = self.query(
            experience.observation,
            top_k=top_k + 1,
            vuln_type=experience.vuln_type,
        )
        return [c for c in candidates if c.id != experience.id][:top_k]

    def get_linked(self, experience: Experience) -> list[Experience]:
        """Retrieve all directly linked experiences.

        Args:
            experience: The experience whose links to follow.

        Returns:
            List of linked experiences for cross-over discovery.
        """
        linked: list[Experience] = []
        for rid in experience.related_ids:
            exp: Experience | None = self.get(rid)
            if exp:
                linked.append(exp)
        return linked

    def count(self) -> int:
        """Return the total number of stored experiences."""
        return self._collection.count()

    def format_experiences_for_prompt(self, experiences: list[Experience]) -> str:
        """Format retrieved experiences as a prompt section.

        Includes linked experiences for cross-over chain discovery.

        Args:
            experiences: Experiences to render.

        Returns:
            Markdown-formatted prompt text, or empty string if no
            experiences are provided.
        """
        if not experiences:
            return ""

        lines: list[str] = [
            "# Past Experience (validated findings on similar targets)",
            "",
            "These chains confirmed real vulnerabilities on targets with a similar "
            "tech stack and endpoint structure to the current target. "
            "Prioritize testing these attack vectors early. "
            "Adapt the chain to the current target — same logic, different URLs/params.",
            "",
        ]

        for exp in experiences:
            lines.append(exp.format_for_prompt())

            linked: list[Experience] = self.get_linked(exp)
            if linked:
                lines.append("")
                lines.append(
                    "**Cross-over chains (similar vuln class, different setup):**"
                )
                for link_exp in linked[:2]:
                    chain_brief: str = " → ".join(
                        step.tool for step in link_exp.chain[:5]
                    )
                    lines.append(
                        f"- [{link_exp.severity.upper()}] {link_exp.finding_title} "
                        f"({', '.join(link_exp.tech_stack[:3])}) — {chain_brief}"
                    )
            lines.append("")

        return "\n".join(lines)
