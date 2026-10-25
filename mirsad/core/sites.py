"""Site database access — the merged corpus of 4,700+ platforms."""

from __future__ import annotations

import json
from functools import lru_cache

from ..config import DATA_DIR

SITES_FILE = DATA_DIR / "sites.json"


@lru_cache(maxsize=1)
def _raw() -> dict:
    if not SITES_FILE.exists():
        raise FileNotFoundError(
            f"{SITES_FILE} is missing. Run: python tools/build_data.py"
        )
    return json.loads(SITES_FILE.read_text(encoding="utf-8"))


def meta() -> dict:
    return _raw().get("_meta", {})


def all_sites(kind: str | None = None) -> list[dict]:
    sites = _raw().get("sites", [])
    if kind:
        sites = [s for s in sites if s.get("kind") == kind]
    return sites


def select(
    kind: str,
    tier: int = 3,
    categories: list[str] | None = None,
    exclude: list[str] | None = None,
    include_nsfw: bool = False,
    include_disabled: bool = False,
    names: list[str] | None = None,
) -> list[dict]:
    """Filter the corpus down to the sites this run should touch."""
    cats = {c.lower() for c in (categories or [])}
    ex = {e.lower() for e in (exclude or [])}
    wanted = {n.lower() for n in (names or [])}
    out = []
    for site in all_sites(kind):
        if not include_disabled and site.get("disabled"):
            continue
        if site.get("tier", 3) > tier:
            continue
        if site.get("nsfw") and not include_nsfw:
            continue
        if cats and site.get("category", "misc").lower() not in cats:
            continue
        if ex and (site.get("id", "").lower() in ex
                   or site.get("name", "").lower() in ex
                   or site.get("domain", "").lower() in ex):
            continue
        if wanted and not (
            site.get("id", "").lower() in wanted
            or site.get("name", "").lower() in wanted
            or site.get("domain", "").lower() in wanted
        ):
            continue
        out.append(site)
    return out


def categories() -> dict[str, int]:
    counts: dict[str, int] = {}
    for site in all_sites():
        key = site.get("category", "misc")
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def stats() -> dict:
    users = all_sites("username")
    emails = all_sites("email")
    tiers = {1: 0, 2: 0, 3: 0}
    for site in users:
        tiers[site.get("tier", 3)] = tiers.get(site.get("tier", 3), 0) + 1
    sources: dict[str, int] = {}
    for site in users + emails:
        for src in site.get("sources", []):
            sources[src] = sources.get(src, 0) + 1
    return {
        "username_sites": len(users),
        "email_sites": len(emails),
        "total": len(users) + len(emails),
        "tiers": tiers,
        "sources": sources,
        "categories": len(categories()),
        "built_from": meta().get("built_from", {}),
    }


def find(name: str) -> list[dict]:
    needle = name.lower()
    return [
        s for s in all_sites()
        if needle in s.get("id", "").lower()
        or needle in s.get("name", "").lower()
        or needle in s.get("domain", "").lower()
    ]
