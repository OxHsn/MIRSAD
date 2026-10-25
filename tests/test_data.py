"""Data-model and database integrity tests."""

from __future__ import annotations

import re

from mirsad.core import sites as site_db
from mirsad.core.models import FOUND, Finding, Report, base_domain


def test_base_domain_and_aliases():
    assert base_domain("api.dailymotion.com") == "dailymotion.com"
    assert base_domain("threads.net") == "threads.com"
    assert base_domain("twitter.com") == "x.com"


def test_dedupe_prefers_confidence_and_keeps_url():
    report = Report(target="alice", target_type="username")
    low = Finding(module="site", kind="account", platform="GitHub", identifier="alice",
                  status=FOUND, confidence=0.7, url="https://github.com/alice",
                  data={"domain": "github.com"})
    high = Finding(module="github", kind="account", platform="GitHub", identifier="alice",
                   status=FOUND, confidence=1.0, data={"domain": "api.github.com"})
    report.add(low)
    report.add(high)
    report.dedupe()
    assert len(report.findings) == 1
    assert report.findings[0].confidence == 1.0
    assert report.findings[0].url == "https://github.com/alice"


def test_graph_ingests_accounts():
    report = Report(target="alice", target_type="username")
    report.add(Finding(module="site", kind="account", platform="GitHub", identifier="alice",
                       status=FOUND, confidence=1.0, url="https://github.com/alice",
                       data={"domain": "github.com", "emails": ["a@b.com"]}))
    kinds = report.graph.counts()
    assert kinds.get("account") == 1
    assert kinds.get("email") == 1


def test_site_database_is_consistent():
    stats = site_db.stats()
    assert stats["username_sites"] > 3500
    assert stats["email_sites"] > 180
    seen = set()
    for site in site_db.all_sites():
        assert site["kind"] in ("username", "email")
        assert site["tier"] in (1, 2, 3)
        assert site["probe"]
        # unresolved {token} placeholders are only acceptable when a pre_check
        # supplies them (BBC's nonce, for example)
        if re.search(r"\{[a-z_]{2,}\}", site["probe"]):
            assert site.get("pre_check"), site["probe"]
        key = (site["kind"], site["domain"])
        assert key not in seen, f"duplicate definition for {key}"
        seen.add(key)


def test_tier_selection_is_a_subset():
    tier1 = site_db.select("username", tier=1)
    tier3 = site_db.select("username", tier=3)
    assert 50 < len(tier1) < len(tier3)


def test_handlers_are_registered():
    from mirsad.modules import email_handlers  # noqa: F401
    from mirsad.modules.base import HANDLERS
    assert {"adobe", "amazon", "github_email", "instagram", "twitter_email"} <= set(HANDLERS)


def test_every_handler_reference_exists():
    from mirsad.modules import email_handlers  # noqa: F401
    from mirsad.modules.base import HANDLERS
    for site in site_db.all_sites("email"):
        if site.get("handler"):
            assert site["handler"] in HANDLERS, site["handler"]
