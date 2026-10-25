"""Username enumeration across the merged platform corpus."""

from __future__ import annotations

from collections.abc import Callable

from ..config import Settings
from ..core import sites as site_db
from ..core.http import Fetcher
from ..core.models import FOUND, Finding
from .base import run_sites


def normalize(value: str) -> str:
    value = value.strip()
    if value.startswith("@"):
        value = value[1:]
    return value.strip("/").split("/")[-1]


async def scan(
    fetcher: Fetcher,
    target: str,
    settings: Settings,
    on_progress: Callable[[int, int, Finding], None] | None = None,
    names: list[str] | None = None,
) -> list[Finding]:
    username = normalize(target)
    selected = site_db.select(
        "username",
        tier=settings.tier,
        categories=settings.categories,
        exclude=settings.exclude,
        include_nsfw=settings.include_nsfw,
        names=names,
    )
    findings = await run_sites(fetcher, selected, username, "username", on_progress)
    findings.sort(key=lambda f: (f.status != FOUND, f.platform.lower()))
    return findings
