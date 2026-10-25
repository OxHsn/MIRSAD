"""Email pattern engine: permutations + company pattern index.

The permutation generator is Blackbird's approach; the company index is a
383k-domain corpus of dominant local-part patterns (P01–P15) so a name plus
a company domain yields an honestly-graded likely address.
"""

from __future__ import annotations

import gzip
import json
import re
from functools import lru_cache
from itertools import permutations as _itertools

from ..config import DATA_DIR

COMPANY_FILE = DATA_DIR / "company_patterns.json.gz"
SEPARATORS = ["", ".", "_", "-"]

TEMPLATES = {
    "P01": "{first}",
    "P02": "{last}",
    "P03": "{first}{last}",
    "P04": "{first}.{last}",
    "P05": "{f}{last}",
    "P06": "{f}.{last}",
    "P07": "{first}{l}",
    "P08": "{first}.{l}",
    "P09": "{first}_{last}",
    "P10": "{first}-{last}",
    "P11": "{last}{first}",
    "P12": "{last}.{first}",
    "P13": "{last}{f}",
    "P14": "{last}.{f}",
    "P15": "{f}{l}",
}


def clean(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9\s\-_.]", "", value)
    return value


def split_name(full_name: str) -> tuple[str, str] | None:
    parts = [p for p in re.split(r"\s+", clean(full_name)) if p]
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0], parts[0]
    return parts[0], parts[-1]


def permutations(parts: list[str], style: str = "strict") -> list[str]:
    """All separator-joined orderings of the given name parts."""
    names = [clean(p) for p in parts if clean(p)]
    if not names:
        return []
    if len(names) == 1:
        return names
    out: list[str] = []
    for size in range(1, len(names) + 1):
        for subset in _itertools(names, size):
            if size == 1:
                out.append(subset[0])
                if style == "all":
                    out.extend(["_" + subset[0], subset[0] + "_"])
                continue
            for sep in SEPARATORS:
                perm = sep.join(subset)
                out.append(perm)
                if style == "all" and sep == "":
                    out.extend(["_" + perm, perm + "_"])
    return list(dict.fromkeys(out))


@lru_cache(maxsize=1)
def _company_index() -> dict:
    if not COMPANY_FILE.exists():
        return {}
    try:
        with gzip.open(COMPANY_FILE, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
        data.pop("_meta", None)
        return data
    except Exception:
        return {}


def company_email(full_name: str, domain: str, top: int = 3) -> list[dict]:
    """Grade the most likely addresses for name@company using the pattern index."""
    parts = split_name(full_name)
    if not parts or not domain:
        return []
    first, last = parts
    domain = domain.lower().lstrip("@")
    entry = _company_index().get(domain) or {}
    pattern = entry.get("pattern")
    confidence = float(entry.get("confidence") or 0.0)

    values = {"first": first, "last": last, "f": first[:1], "l": last[:1]}
    ranked: list[tuple[str, str, float]] = []
    if pattern in TEMPLATES:
        ranked.append((pattern, TEMPLATES[pattern].format(**values), max(0.55, confidence)))
    # fill the rest with the generic industry ranking
    generic = ["P04", "P03", "P05", "P01", "P06", "P02"]
    for pid in generic:
        local = TEMPLATES[pid].format(**values)
        if any(local == r[1] for r in ranked):
            continue
        ranked.append((pid, local, 0.25 if not pattern else 0.2))
    return [
        {"email": f"{local}@{domain}", "pattern": pid, "confidence": round(conf, 2)}
        for pid, local, conf in ranked[:top]
    ]


def username_candidates(email: str, limit: int = 6) -> list[str]:
    """Local-part variants worth feeding back into a username scan."""
    local = email.split("@", 1)[0].lower()
    base = re.split(r"[+._\-]", local)[0]
    out = [local, base]
    if len(base) > 12:
        out.append(base[:12])
    return list(dict.fromkeys([c for c in out if 2 < len(c) < 40]))[:limit]
