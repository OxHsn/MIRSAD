"""Domain intelligence: MX, SPF, DMARC, provider, disposable, harvesting."""

from __future__ import annotations

import asyncio
import json
import re
from functools import lru_cache

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..config import DATA_DIR, Settings
from ..core.http import Fetcher
from ..core.models import FOUND, NOT_FOUND, Finding

DISPOSABLE_FILE = DATA_DIR / "disposable_domains.json"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

PROVIDERS = {
    "google": "Google Workspace", "googlemail": "Google Workspace",
    "outlook": "Microsoft 365", "protection.outlook": "Microsoft 365",
    "protonmail": "Proton Mail", "proton": "Proton Mail",
    "zoho": "Zoho Mail", "yandex": "Yandex Mail", "mail.ru": "Mail.ru",
    "icloud": "iCloud Mail", "qq.com": "Tencent Exmail", "exmail": "Tencent Exmail",
    "mimecast": "Mimecast", "proofpoint": "Proofpoint", "barracuda": "Barracuda",
    "amazonses": "Amazon SES", "secureserver": "GoDaddy",
}


@lru_cache(maxsize=1)
def disposable_domains() -> set[str]:
    try:
        return set(json.loads(DISPOSABLE_FILE.read_text(encoding="utf-8")))
    except Exception:
        return set()


def is_disposable(domain: str) -> bool:
    domain = domain.lower()
    data = disposable_domains()
    return domain in data or any(domain.endswith("." + d) for d in data if len(d) > 3)


def _resolver() -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 3.0
    resolver.timeout = 3.0
    return resolver


DOH_ENDPOINTS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")


async def _doh(fetcher: Fetcher, name: str, rtype: str) -> list[str]:
    """DNS over HTTPS fallback — works when UDP/53 is blocked or filtered."""
    for endpoint in DOH_ENDPOINTS:
        data = await fetcher.json(
            f"{endpoint}?name={name}&type={rtype}",
            headers={"Accept": "application/dns-json"},
            cache=False,
        )
        answers = (data or {}).get("Answer") if isinstance(data, dict) else None
        if answers:
            out = []
            for row in answers:
                value = str(row.get("data", "")).strip()
                if rtype == "TXT":
                    value = value.strip('"').replace('" "', "")
                elif rtype == "MX":
                    value = value.rstrip(".")
                out.append(value)
            return out
    return []


async def _query(fetcher: Fetcher | None, name: str, rtype: str) -> list[str]:
    try:
        answers = await _resolver().resolve(name, rtype)
        out = []
        for record in answers:
            if rtype == "TXT":
                try:
                    out.append(b"".join(record.strings).decode("utf-8", "ignore"))
                except Exception:
                    out.append(str(record).strip('"'))
            elif rtype == "MX":
                out.append(f"{record.preference} {record.exchange.to_text().rstrip('.')}")
            else:
                out.append(record.to_text())
        if out:
            return out
    except Exception:
        pass
    if fetcher is not None:
        return await _doh(fetcher, name, rtype)
    return []


async def _txt(name: str, fetcher: Fetcher | None = None) -> list[str]:
    return await _query(fetcher, name, "TXT")


async def _mx(domain: str, fetcher: Fetcher | None = None) -> list[str]:
    return sorted(await _query(fetcher, domain, "MX"))


async def _records(name: str, rtype: str, fetcher: Fetcher | None = None) -> list[str]:
    return await _query(fetcher, name, rtype)


def provider_for(mx: list[str]) -> str | None:
    joined = " ".join(mx).lower()
    for needle, label in PROVIDERS.items():
        if needle in joined:
            return label
    return None


async def investigate(fetcher: Fetcher, domain: str, settings: Settings, deep: bool = False) -> list[Finding]:
    domain = domain.strip().lower().lstrip("@")
    findings: list[Finding] = []

    mx, txt, a, ns = await asyncio.gather(
        _mx(domain, fetcher), _txt(domain, fetcher),
        _records(domain, "A", fetcher), _records(domain, "NS", fetcher),
    )
    dmarc_txt = await _txt(f"_dmarc.{domain}", fetcher)

    spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    dmarc = next((t for t in dmarc_txt if t.lower().startswith("v=dmarc1")), None)
    provider = provider_for(mx)

    data = {
        "mx": mx, "spf": bool(spf), "spf_record": spf,
        "dmarc": bool(dmarc), "dmarc_record": dmarc,
        "provider": provider, "a": a, "ns": ns,
        "disposable": is_disposable(domain),
        "has_mail": bool(mx),
    }
    findings.append(Finding(
        module="domain", kind="dns", platform="DNS",
        identifier=domain, status=FOUND if (mx or a) else NOT_FOUND,
        confidence=0.95, data=data, source="mirsad", tags=["dns", "email-security"],
    ))

    if provider:
        findings.append(Finding(
            module="domain", kind="identity", platform="Mail provider",
            identifier=domain, status=FOUND, confidence=0.9,
            data={"provider": provider}, source="mirsad", tags=["infrastructure"],
        ))

    if data["disposable"]:
        findings.append(Finding(
            module="domain", kind="identity", platform="Disposable email",
            identifier=domain, status=FOUND, confidence=0.9,
            data={"note": "domain belongs to a throwaway mail provider"},
            source="mirsad", tags=["risk"],
        ))

    if deep:
        findings.extend(await _deep(fetcher, domain, settings))

    return findings


async def _deep(fetcher: Fetcher, domain: str, settings: Settings) -> list[Finding]:
    """Subdomains from certificate transparency + emails from the public site."""
    out: list[Finding] = []

    crt = await fetcher.json(f"https://crt.sh/?q=%25.{domain}&output=json")
    if isinstance(crt, list):
        subs: set[str] = set()
        for row in crt[:1500]:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if "@" in name or " " in name:  # CT sometimes stores emails
                    continue
                if name.endswith(domain) and name != domain and len(name) < 120:
                    subs.add(name)
        if subs:
            out.append(Finding(
                module="domain", kind="dns", platform="Certificate Transparency",
                identifier=domain, status=FOUND, confidence=0.9,
                data={"subdomains": sorted(subs)[:300], "count": len(subs)},
                source="crt.sh", tags=["subdomains"],
            ))

    for scheme in ("https://", "http://"):
        resp = await fetcher.get(f"{scheme}{domain}")
        if resp.ok and resp.text:
            emails = sorted(set(EMAIL_RE.findall(resp.text[:400_000])))
            emails = [e for e in emails if not e.lower().endswith((".png", ".jpg", ".gif", ".webp"))]
            if emails:
                out.append(Finding(
                    module="domain", kind="identity", platform="Website harvest",
                    identifier=domain, status=FOUND, confidence=0.8,
                    data={"emails": emails[:100], "count": len(emails)},
                    source=scheme.rstrip("/"), tags=["harvest"],
                ))
            break
    return out
