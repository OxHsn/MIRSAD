"""Orchestrator: run modules, then branch on whatever they discovered.

The branching idea is Sylva's: an email reveals a domain, a username reveals a
GitHub profile, a GitHub profile reveals commit emails — each discovery is a
new query. MIRSAD does the same with an explicit depth and budget so a scan
never explodes.
"""

from __future__ import annotations

import re
import time
from collections import deque
from collections.abc import Callable

from ..config import Settings
from ..modules import breach as breach_mod
from ..modules import domain as domain_mod
from ..modules import email_accounts, github, google, patterns
from ..modules import username as username_mod
from . import scoring
from .http import Fetcher
from .models import FOUND, UNKNOWN, Finding, Report
from .ui import ProgressUI

DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)


def detect_type(value: str) -> str:
    value = value.strip()
    if EMAIL_RE.match(value):
        return "email"
    if value.startswith("@") or " " in value:
        return "username"
    if DOMAIN_RE.match(value.lower()) and "." in value:
        return "domain"
    return "username"


class Orchestrator:
    def __init__(self, settings: Settings, ui: ProgressUI | None = None,
                 on_event: Callable[[str, dict], None] | None = None) -> None:
        self.settings = settings
        self.ui = ui
        self.on_event = on_event
        self.queue: deque[tuple[str, str, int]] = deque()
        self.visited: set[tuple[str, str]] = set()
        self.branch_budget = settings.max_branch

    # ------------------------------------------------------------------ public
    async def run(self, target: str, kind: str = "auto", deep: bool = False) -> Report:
        target = target.strip()
        kind = detect_type(target) if kind == "auto" else kind
        report = Report(target=target, target_type=kind)
        report.meta = {
            "version": "1.0.0",
            "settings": {
                "tier": self.settings.tier, "depth": self.settings.depth,
                "concurrency": self.settings.concurrency, "strict_email": self.settings.strict_email,
            },
        }

        self.queue.append((target, kind, 0))
        if kind == "email":
            domain = target.split("@", 1)[1]
            self.queue.append((domain, "domain", 1))

        async with Fetcher(self.settings, cache=_cache(self.settings)) as fetcher:
            if self.ui:
                self.ui.set_header(target)
            while self.queue:
                value, node_kind, depth = self.queue.popleft()
                key = (node_kind, value.lower())
                if key in self.visited:
                    continue
                self.visited.add(key)
                try:
                    await self._dispatch(fetcher, report, value, node_kind, depth, deep)
                except Exception as exc:  # keep going
                    report.add(Finding(
                        module=node_kind, kind="note", platform="orchestrator",
                        identifier=value, status=UNKNOWN,
                        data={"reason": type(exc).__name__, "detail": str(exc)[:200]},
                    ))
            report.stats.update(fetcher.stats())
            report.stats["nodes"] = len(self.visited)

        report.dedupe()
        report.score = scoring.compute(report)
        report.finished = time.time()
        report.stats.update(report.summary())
        if self.ui:
            self.ui.log(f"[dim]branched into {len(self.visited)} node(s)[/]")
        return report

    # ---------------------------------------------------------------- dispatch
    async def _dispatch(self, fetcher: Fetcher, report: Report, value: str,
                        kind: str, depth: int, deep: bool) -> None:
        if kind == "email":
            await self._email(fetcher, report, value, depth)
        elif kind == "username":
            await self._username(fetcher, report, value, depth)
        elif kind == "domain":
            await self._domain(fetcher, report, value, depth, deep)
        elif kind == "github":
            await self._github(fetcher, report, value, depth)

    # ----------------------------------------------------------------- modules
    async def _email(self, fetcher: Fetcher, report: Report, email: str, depth: int) -> None:
        if self.ui:
            from ..core import sites as site_db
            self.ui.add("email", len(site_db.select("email", tier=self.settings.tier,
                                                     include_nsfw=self.settings.include_nsfw)))

        def progress(done: int, total: int, finding: Finding) -> None:
            if self.ui:
                self.ui.tick("email", finding.platform, finding.status == FOUND)
            self._emit("finding", finding)

        findings = await email_accounts.scan(fetcher, email, self.settings, progress)
        report.extend(findings)

        extra = await google.check(fetcher, email)
        report.add(extra)
        self._emit("finding", extra)

        for f in await breach_mod.investigate(fetcher, email, self.settings):
            report.add(f)
            self._emit("finding", f)

        domain = email.split("@", 1)[1]
        if depth + 1 <= self.settings.depth and self.branch_budget > 0:
            self._enqueue(domain, "domain", depth + 1)

        if self.settings.expand and depth + 1 <= self.settings.depth:
            for candidate in patterns.username_candidates(email, limit=2):
                self._enqueue(candidate, "username", depth + 1)

    async def _username(self, fetcher: Fetcher, report: Report, name: str, depth: int) -> None:
        if self.ui:
            from ..core import sites as site_db
            self.ui.add("username", len(site_db.select("username", tier=self.settings.tier,
                                                        include_nsfw=self.settings.include_nsfw)))

        def progress(done: int, total: int, finding: Finding) -> None:
            if self.ui:
                self.ui.tick("username", finding.platform, finding.status == FOUND)
            self._emit("finding", finding)

        findings = await username_mod.scan(fetcher, name, self.settings, progress)
        report.extend(findings)

        platforms = {f.platform.lower() for f in findings if f.status == FOUND}
        if depth + 1 <= self.settings.depth and ("github" in platforms or self.settings.expand):
            self._enqueue(name, "github", depth + 1)

    async def _github(self, fetcher: Fetcher, report: Report, name: str, depth: int) -> None:
        if self.ui:
            self.ui.add("github", 8)
        findings = await github.investigate(fetcher, name, self.settings)
        for f in findings:
            report.add(f)
            self._emit("finding", f)
            if self.ui:
                self.ui.tick("github", f.platform, f.status == FOUND)

        if depth + 1 > self.settings.depth or not self.settings.expand:
            return
        for f in findings:
            if f.kind != "identity":
                continue
            for email in (f.data.get("emails") or [])[:3]:
                if "noreply" in email or email.endswith("@users.noreply.github.com"):
                    continue
                self._enqueue(email, "email", depth + 1)

    async def _domain(self, fetcher: Fetcher, report: Report, domain: str, depth: int, deep: bool) -> None:
        if self.ui:
            self.ui.add(f"domain:{domain}", 4)
        findings = await domain_mod.investigate(fetcher, domain, self.settings, deep=deep)
        for f in findings:
            report.add(f)
            self._emit("finding", f)
            if self.ui:
                self.ui.tick(f"domain:{domain}", f.platform, f.status == FOUND)

        if depth + 1 > self.settings.depth:
            return
        for f in findings:
            for email in (f.data.get("emails") or [])[:5]:
                if email.split("@")[-1].lower() == domain.lower():
                    self._enqueue(email, "email", depth + 1)

    # ------------------------------------------------------------------ branch
    def _enqueue(self, value: str, kind: str, depth: int) -> None:
        if depth > self.settings.depth or self.branch_budget <= 0:
            return
        key = (kind, value.lower())
        if key in self.visited:
            return
        self.branch_budget -= 1
        self.queue.append((value, kind, depth))
        if self.ui:
            self.ui.log(f"[dim]branch → {kind}:{value}[/]")

    def _emit(self, event: str, payload) -> None:
        if self.on_event:
            try:
                self.on_event(event, payload if isinstance(payload, dict) else payload.to_dict())
            except Exception:
                pass


def _cache(settings: Settings):
    if not settings.use_cache:
        return None
    from .cache import Cache
    return Cache(ttl=settings.cache_ttl)
