"""Verdict-engine tests — the part that decides truth vs noise."""

from __future__ import annotations

from mirsad.core.detect import classify, looks_blocked, looks_parked, non_discriminating
from mirsad.core.models import BLOCKED, FOUND, NOT_FOUND, UNKNOWN


def two_marker(e_code=200, e_text="", m_code=404, m_text=""):
    return {"check": {"mode": "two_marker",
                      "exists": {"code": e_code, "text": e_text},
                      "missing": {"code": m_code, "text": m_text}}}


def test_two_marker_present():
    site = two_marker(e_text='"login":"alice"', m_text="not found")
    v = classify(site, 200, '{"login":"alice","id":1}', "https://x.com/alice")
    assert v.status == FOUND
    assert v.confidence > 0.9


def test_two_marker_absent():
    site = two_marker(e_text='"login"', m_text="not found")
    v = classify(site, 404, "not found", "https://x.com/alice")
    assert v.status == NOT_FOUND


def test_absence_marker_wins_on_collision():
    # the "not found" body contains the presence marker as a substring
    site = two_marker(200, '"userId":', 200, '"userId":0')
    v = classify(site, 200, '{"userId":0}', "https://x.com/alice")
    assert v.status == NOT_FOUND


def test_ambiguous_json_markers_are_not_a_hit():
    # Figma-style payload listing both enum values
    site = two_marker(200, "sign_in", 200, "sign_up")
    v = classify(site, 200, '{"available_methods":["sign_in","sign_up"]}', "https://figma.com/x")
    assert v.status == UNKNOWN


def test_rate_limit_and_5xx_are_unknown():
    site = two_marker(e_text="x", m_text="y")
    assert classify(site, 429, "x", "https://x.com/a").status == UNKNOWN
    assert classify(site, 503, "x", "https://x.com/a").status == UNKNOWN


def test_waf_and_parked_detection():
    site = two_marker(e_text="x", m_text="y")
    assert classify(site, 200, "Just a moment...", "https://x.com/a").status == BLOCKED
    assert classify(site, 200, "This domain is for sale!", "https://x.com/a").status == UNKNOWN
    assert looks_blocked("Just a moment...")
    assert looks_parked("buy this domain today")


def test_redirect_stub_is_unknown():
    site = {"check": {"mode": "status"}}
    body = '<html><meta http-equiv="refresh" content="0;url=/login"></html>'
    assert classify(site, 200, body, "https://x.com/alice").status == UNKNOWN


def test_status_mode_requires_identifier_in_content():
    site = {"check": {"mode": "status"}}
    generic = "<html><title>Bitchute</title><meta content='/channel/alice/'>" + "x" * 4000
    assert classify(site, 200, generic, "https://bitchute.com/channel/alice/", needle="alice").status == UNKNOWN
    real = "<html><title>alice (Alice) · GitHub</title></html>"
    assert classify(site, 200, real, "https://github.com/alice", needle="alice").status == FOUND


def test_message_mode():
    site = {"check": {"mode": "message", "missing": {"text": ["No such user"]}}}
    assert classify(site, 200, "No such user here", "https://x.com/a").status == NOT_FOUND
    assert classify(site, 200, "<title>alice profile</title>", "https://x.com/alice", needle="alice").status == FOUND


def test_non_discriminating_urls():
    assert non_discriminating("https://site.com/")
    assert non_discriminating("https://site.com/users/filter?search=alice")
    assert non_discriminating("https://site.com/search?q=alice")
    assert not non_discriminating("https://site.com/alice")


def test_offsite_search_endpoint_is_ignored():
    site = {"check": {"mode": "message", "exists": {"text": ["profile"]}}}
    v = classify(site, 200, "profile", "https://site.com/users/filter?search=alice", needle="alice")
    assert v.status == UNKNOWN
