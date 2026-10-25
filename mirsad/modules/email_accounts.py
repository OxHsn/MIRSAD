"""Email -> account existence across 200+ services.

Three layers, merged:
* declarative two-marker probes (WhatsMyName / MailAccess)
* session-bootstrapped probes (CSRF + cookies)
* bespoke handlers for sites whose answer lives in JSON logic
  (ported behaviour from holehe / Zehef / Eyes)
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable

from ..config import Settings
from ..core import sites as site_db
from ..core.http import Fetcher
from ..core.models import FOUND, NOT_FOUND, UNKNOWN, Finding
from . import email_handlers  # noqa: F401  (registers bespoke probes)
from .base import run_sites

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

PLACEHOLDER_LOCALS = {
    "test", "tests", "testing", "example", "sample", "demo", "user", "admin",
    "info", "mail", "email", "foo", "bar", "baz", "john.doe", "johndoe",
    "noreply", "no-reply", "donotreply", "someone", "anyone", "name",
}
PLACEHOLDER_DOMAINS = {
    "example.com", "example.org", "example.net", "test.com", "domain.com",
    "email.com", "mail.com", "localhost", "test.test", "invalid",
}


def is_placeholder(email: str) -> bool:
    local, _, domain = email.partition("@")
    return local.split("+")[0] in PLACEHOLDER_LOCALS and domain in PLACEHOLDER_DOMAINS


def valid(email: str) -> bool:
    return bool(EMAIL_RE.match(email.strip()))


def control_email(email: str) -> str:
    domain = email.split("@", 1)[1] if "@" in email else "example.com"
    return f"mirsad{secrets.token_hex(6)}@{domain}"


async def scan(
    fetcher: Fetcher,
    target: str,
    settings: Settings,
    on_progress: Callable[[int, int, Finding], None] | None = None,
    names: list[str] | None = None,
) -> list[Finding]:
    email = target.strip().lower()
    if not valid(email):
        return []
    if is_placeholder(email):
        return [Finding(
            module="email", kind="note", platform="input-check", identifier=email,
            status="info", confidence=1.0,
            data={"note": "placeholder address (test@example.com style) — account probing skipped"},
            source="mirsad",
        )]

    selected = site_db.select(
        "email",
        tier=settings.tier,
        categories=settings.categories,
        exclude=settings.exclude,
        include_nsfw=settings.include_nsfw,
        names=names,
    )
    findings = await run_sites(fetcher, selected, email, "email", on_progress)

    if settings.strict_email:
        await _disambiguate(fetcher, findings, email)

    findings.sort(key=lambda f: (f.status != FOUND, f.platform.lower()))
    return findings


async def _disambiguate(fetcher: Fetcher, findings: list[Finding], email: str) -> None:
    """Control-email test: if a random address also 'exists', the site is catch-all."""
    from ..core.models import base_domain
    from .base import probe_site
    lookup: dict[str, dict] = {}
    for site in site_db.select("email", tier=3, include_disabled=False):
        lookup.setdefault(site.get("name", "").lower(), site)
        if site.get("domain"):
            lookup.setdefault(base_domain(site["domain"]), site)
    control = control_email(email)
    for finding in [f for f in findings if f.status == FOUND]:
        site = lookup.get(base_domain(finding.data.get("domain", ""))) or lookup.get(finding.platform.lower())
        if not site:
            continue
        probe = await probe_site(fetcher, site, control, "email")
        if probe.status == FOUND:
            finding.status = UNKNOWN
            finding.confidence = 0.0
            finding.data["reason"] = "catch_all_domain"
        elif probe.status == NOT_FOUND:
            finding.confidence = min(0.99, finding.confidence + 0.03)
