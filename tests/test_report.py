"""Pattern engine + report rendering tests."""

from __future__ import annotations

import json

from mirsad.core.models import FOUND, Finding, Report
from mirsad.modules import patterns
from mirsad.report.html import render


def test_split_name():
    assert patterns.split_name("Linus Torvalds") == ("linus", "torvalds")
    assert patterns.split_name("  Ada   Lovelace ") == ("ada", "lovelace")
    assert patterns.split_name("") is None


def test_permutations_include_common_forms():
    out = patterns.permutations(["john", "smith"])
    assert "john.smith" in out
    assert "jsmith" not in out  # that's a template, not a permutation
    assert "johnsmith" in out


def test_username_candidates_from_email():
    cands = patterns.username_candidates("john.smith+tag@example.org")
    assert "john" in cands
    assert all(2 < len(c) < 40 for c in cands)


def test_company_email_grades_confidence():
    rows = patterns.company_email("Linus Torvalds", "linux-foundation.org")
    assert rows and all("@" in r["email"] for r in rows)
    assert all(0 <= r["confidence"] <= 1 for r in rows)


def _report() -> Report:
    report = Report(target="alice", target_type="username")
    report.add(Finding(module="username", kind="account", platform="GitHub", identifier="alice",
                       status=FOUND, confidence=0.9, url="https://github.com/alice",
                       data={"domain": "github.com", "title": "alice"}))
    report.add(Finding(module="breach", kind="breach", platform="HIBP", identifier="alice",
                       status=FOUND, confidence=0.9, data={"breaches": [{"name": "Adobe"}]}))
    report.score = {"score": 42, "band": "moderate", "drivers": [
        {"label": "Account footprint", "points": 12, "detail": "1 account", "severity": "info"}]}
    report.finished = report.started + 1
    return report


def test_html_report_is_self_contained_and_complete():
    html = render(_report())
    assert "__TARGET__" not in html
    assert "const DATA = {" in html
    assert "https://github.com/alice" in html
    assert "<script src=" not in html  # no CDN
    payload = html.split("const DATA = ", 1)[1].split(";\n", 1)[0]
    data = json.loads(payload)
    assert data["target"] == "alice"
    assert data["graph"]["nodes"]


def test_json_export_roundtrip(tmp_path):
    from mirsad.report import export
    path = export.to_json(_report(), tmp_path / "r.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["target"] == "alice"
    assert data["findings"]


def test_csv_export(tmp_path):
    from mirsad.report import export
    path = export.to_csv(_report(), tmp_path / "r.csv")
    text = path.read_text(encoding="utf-8-sig")
    assert "platform" in text.splitlines()[0]
    assert "GitHub" in text
