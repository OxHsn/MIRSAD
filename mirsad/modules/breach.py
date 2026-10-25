"""Breach intelligence: HIBP, HudsonRock stealer logs, and local breach dumps.

Mechanisms merged from h8mail (API fan-out + local .gz search) and
Zehef (HudsonRock cavalier endpoint).
"""

from __future__ import annotations

import asyncio
import gzip
from pathlib import Path

from ..config import Settings
from ..core.http import Fetcher
from ..core.models import FOUND, INFO, NOT_FOUND, UNKNOWN, Finding

HUDSON_ROCK = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
HUDSON_KEY = "ROCKHUDSONROCK"
TEXT_SUFFIXES = {".txt", ".csv", ".tsv", ".log", ".jsonl", ""}


async def hibp(fetcher: Fetcher, email: str, settings: Settings) -> Finding | None:
    if not settings.hibp_key:
        return None
    resp = await fetcher.request(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
        headers={"hibp-api-key": settings.hibp_key, "User-Agent": "MIRSAD"},
        cache=False,
    )
    finding = Finding(
        module="breach", kind="breach", platform="HaveIBeenPwned",
        identifier=email, status=UNKNOWN, url="https://haveibeenpwned.com/",
        source="h8mail", tags=["breach"],
    )
    if resp.status == 404:
        finding.status = NOT_FOUND
        finding.confidence = 0.9
        finding.data["reason"] = "no_breach"
        return finding
    if resp.status == 401:
        finding.data["reason"] = "invalid_api_key"
        return finding
    if resp.status == 429:
        finding.data["reason"] = "rate_limited"
        return finding
    if not resp.ok:
        finding.data["reason"] = resp.error or f"http_{resp.status}"
        return finding

    import json
    try:
        breaches = json.loads(resp.text)
    except Exception:
        finding.data["reason"] = "bad_payload"
        return finding
    if not isinstance(breaches, list):
        return finding

    finding.status = FOUND
    finding.confidence = 0.98
    finding.data.update({
        "count": len(breaches),
        "breaches": [
            {
                "name": b.get("Name"), "domain": b.get("Domain"),
                "date": b.get("BreachDate"), "pwn_count": b.get("PwnCount"),
                "data_classes": b.get("DataClasses", []),
                "verified": b.get("IsVerified"),
            }
            for b in breaches
        ],
        "passwords": any("Passwords" in (b.get("DataClasses") or []) for b in breaches),
        "hash": any("Password hints" in (b.get("DataClasses") or []) for b in breaches),
    })
    return finding


async def hudson_rock(fetcher: Fetcher, email: str) -> Finding:
    resp = await fetcher.request(
        HUDSON_ROCK,
        headers={"api-key": HUDSON_KEY, "Accept": "application/json"},
        cache=False,
    )
    finding = Finding(
        module="breach", kind="breach", platform="HudsonRock (infostealer)",
        identifier=email, status=UNKNOWN, url="https://www.hudsonrock.com/",
        source="zehef", tags=["breach", "stealer"],
    )
    if not resp.ok:
        finding.data["reason"] = resp.error or f"http_{resp.status}"
        return finding
    import json
    try:
        data = json.loads(resp.text)
    except Exception:
        finding.data["reason"] = "bad_payload"
        return finding

    stealers = (data or {}).get("stealers") or []
    if not stealers:
        finding.status = NOT_FOUND
        finding.confidence = 0.8
        finding.data["reason"] = "no_stealer_log"
        return finding

    first = stealers[0] or {}
    finding.status = FOUND
    finding.confidence = 0.92
    finding.data.update({
        "count": len(stealers),
        "stealer": True,
        "date": first.get("date_compromised"),
        "computer": first.get("computer_name"),
        "os": first.get("operating_system"),
        "ip": first.get("ip"),
        "passwords": bool(first.get("top_passwords")),
        "logins": first.get("top_logins", [])[:10],
        "malware": first.get("malware_path"),
    })
    return finding


def _scan_file(path: Path, email: str, limit: int = 20) -> list[str]:
    """Return matching lines from one dump file (gzip-aware)."""
    hits: list[str] = []
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if email in line:
                    hits.append(line.strip()[:400])
                    if len(hits) >= limit:
                        break
    except (OSError, EOFError):
        return hits
    return hits


async def local_dumps(email: str, settings: Settings) -> Finding | None:
    if not settings.local_breach_dir:
        return None
    root = Path(settings.local_breach_dir)
    if not root.exists():
        return None

    files = [
        p for p in root.rglob("*")
        if p.is_file() and (p.suffix.lower() in TEXT_SUFFIXES or p.suffix.lower() == ".gz")
    ][:500]
    if not files:
        return None

    loop = asyncio.get_running_loop()
    results = await asyncio.gather(*[
        loop.run_in_executor(None, _scan_file, path, email) for path in files
    ])
    hits: list[str] = []
    matched_files: list[str] = []
    for path, found in zip(files, results, strict=False):
        if found:
            matched_files.append(path.name)
            hits.extend(found)

    finding = Finding(
        module="breach", kind="breach", platform="Local breach dumps",
        identifier=email, status=FOUND if hits else NOT_FOUND,
        confidence=0.95 if hits else 0.6,
        source="h8mail", tags=["breach", "local"],
    )
    finding.data.update({
        "files": matched_files[:10], "count": len(matched_files),
        "lines": hits[:20], "passwords": bool(hits),
        "scanned": len(files),
    })
    return finding


async def investigate(fetcher: Fetcher, email: str, settings: Settings) -> list[Finding]:
    tasks = [hudson_rock(fetcher, email), local_dumps(email, settings)]
    hibp_task = hibp(fetcher, email, settings)
    results = await asyncio.gather(*tasks, hibp_task, return_exceptions=True)
    out: list[Finding] = []
    for item in results:
        if isinstance(item, Finding):
            out.append(item)
        elif isinstance(item, Exception):
            out.append(Finding(
                module="breach", kind="breach", platform="breach-check",
                identifier=email, status=UNKNOWN,
                data={"reason": type(item).__name__}, source="mirsad",
            ))
    if not settings.hibp_key:
        out.append(Finding(
            module="breach", kind="note", platform="HaveIBeenPwned",
            identifier=email, status=INFO,
            data={"note": "set HIBP_API_KEY to enable the HIBP breach feed"},
            source="mirsad",
        ))
    return out
