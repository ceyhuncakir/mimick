from __future__ import annotations

from pathlib import Path

import chromadb

from mimick.config import settings
from mimick.logger import get_logger
from mimick.memory.models import Experience

log = get_logger("experience")


class ExperienceStore:
    """Persistent experience memory backed by ChromaDB.

    Stores validated exploitation chains with semantic search over
    observation contexts. Uses ChromaDB's built-in all-MiniLM-L6-v2
    embeddings (local, no API key needed).

    Architecture references:
      - AgentRR: multi-level experience abstraction
      - Memex(RL): indexed memory with full-fidelity chain data
      - A-MEM: dynamic linking between related experiences
    """

    def __init__(self, db_dir: Path) -> None:
        db_dir.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(db_dir))
        self._collection = self._client.get_or_create_collection(
            name=settings.experience_collection,
            metadata={"hnsw:space": "cosine"},
        )
        log.info(
            "Experience store loaded: %d experiences from %s",
            self._collection.count(),
            db_dir,
        )

    def add(self, experience: Experience) -> None:
        """Store a new experience."""
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

        Based on RAG Agents paper findings:
          - Query by current observation state (not task goal)
          - top-2 outperforms top-5 (less noise)
          - Filter by vuln_type when in a specific attack phase
        """
        if self._collection.count() == 0:
            return []

        where: dict | None = None
        conditions: list[dict] = [{"validated": True}]

        if vuln_type:
            conditions.append({"vuln_type": vuln_type})

        if min_severity:
            severity_order = ["info", "low", "medium", "high", "critical"]
            idx = (
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
            results = self._collection.query(
                query_texts=[observation],
                n_results=min(top_k, self._collection.count()),
                where=where,
                include=["documents", "metadatas", "distances"],
            )
        except Exception:
            # Fall back to unfiltered query if filter fails
            results = self._collection.query(
                query_texts=[observation],
                n_results=min(top_k, self._collection.count()),
                include=["documents", "metadatas", "distances"],
            )

        experiences: list[Experience] = []
        if not results["ids"] or not results["ids"][0]:
            return experiences

        for i, exp_id in enumerate(results["ids"][0]):
            doc = results["documents"][0][i] if results["documents"] else ""
            meta = results["metadatas"][0][i] if results["metadatas"] else {}
            distance = results["distances"][0][i] if results["distances"] else 1.0

            # Cosine distance threshold — skip if too dissimilar
            if distance > 0.7:
                continue

            exp = Experience.from_chroma_result(exp_id, doc, meta)
            experiences.append(exp)

        return experiences

    def get(self, experience_id: str) -> Experience | None:
        """Get a specific experience by ID."""
        result = self._collection.get(
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
        """Create a bidirectional link between two experiences."""
        a = self.get(exp_id_a)
        b = self.get(exp_id_b)
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
        """Find experiences related to a given one (for auto-linking).

        Queries by the same observation to find similar chains,
        then filters out the experience itself.
        """
        candidates = self.query(
            experience.observation,
            top_k=top_k + 1,
            vuln_type=experience.vuln_type,
        )
        return [c for c in candidates if c.id != experience.id][:top_k]

    def get_linked(self, experience: Experience) -> list[Experience]:
        """Retrieve all linked experiences for cross-over discovery."""
        linked: list[Experience] = []
        for rid in experience.related_ids:
            exp = self.get(rid)
            if exp:
                linked.append(exp)
        return linked

    def count(self) -> int:
        return self._collection.count()

    def format_experiences_for_prompt(self, experiences: list[Experience]) -> str:
        """Format retrieved experiences as a prompt section.

        Includes linked experiences for cross-over chain discovery.
        """
        if not experiences:
            return ""

        lines = [
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

            # Surface cross-over links
            linked = self.get_linked(exp)
            if linked:
                lines.append("")
                lines.append(
                    "**Cross-over chains (similar vuln class, different setup):**"
                )
                for link in linked[:2]:
                    chain_brief = " → ".join(step.tool for step in link.chain[:5])
                    lines.append(
                        f"- [{link.severity.upper()}] {link.finding_title} "
                        f"({', '.join(link.tech_stack[:3])}) — {chain_brief}"
                    )
            lines.append("")

        return "\n".join(lines)
