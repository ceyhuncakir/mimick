"""Automatic bidirectional linking between related experiences."""

from __future__ import annotations

from mimick.logger import get_logger
from mimick.memory.models import Experience
from mimick.memory.store import ExperienceStore

log = get_logger("experience.linker")


def auto_link(store: ExperienceStore, experience: Experience) -> None:
    """Link a new experience to similar existing ones.

    Finds experiences with similar observations or the same vulnerability
    type and creates bidirectional links for cross-over chain discovery.

    Args:
        store: The experience store to search and update.
        experience: The newly created experience to link.
    """
    related: list[Experience] = store.find_related(experience, top_k=3)

    for candidate in related:
        store.link(experience.id, candidate.id)
        log.info(
            "Auto-linked %s (%s) <-> %s (%s)",
            experience.id,
            experience.finding_title[:40],
            candidate.id,
            candidate.finding_title[:40],
        )
