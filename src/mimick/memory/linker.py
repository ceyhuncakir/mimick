from __future__ import annotations

from mimick.logger import get_logger
from mimick.memory.models import Experience
from mimick.memory.store import ExperienceStore

log = get_logger("experience.linker")


def auto_link(store: ExperienceStore, experience: Experience) -> None:
    """Automatically link a new experience to similar existing ones.

    Inspired by A-MEM's Zettelkasten-style dynamic linking:
    finds experiences with similar observations or the same vuln_type
    and creates bidirectional links for cross-over chain discovery.
    """
    related = store.find_related(experience, top_k=3)

    for candidate in related:
        # Link if same vuln type or if observation similarity is high
        # (find_related already filters by similarity via ChromaDB query)
        store.link(experience.id, candidate.id)
        log.info(
            "Auto-linked %s (%s) <-> %s (%s)",
            experience.id,
            experience.finding_title[:40],
            candidate.id,
            candidate.finding_title[:40],
        )
