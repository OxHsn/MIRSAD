"""Unified verdict engine.

Every upstream tool answers the same question differently:

* Sherlock   -> status code, error message in body, redirect target
* WhatsMyName-> two independent markers (exists code+string, missing code+string)
* MailAccess -> the same two markers plus WAF / rate-limit gates and a
                "non-discriminating URL" guard
* holehe     -> bespoke per-site parsers returning exists True/False/None

MIRSAD normalises all of them into one ``Verdict`` so a single engine can
run 4,800 site definitions without caring where the definition came from.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

from .models import BLOCKED, FOUND, NOT_FOUND, UNKNOWN

# WAF / anti-bot fingerprints (Sherlock's list + a few common ones).
WAF_MARKERS = (
    "challenge-running",
    '<span id="challenge-error-text">',
    "AwsWafIntegration.forceRefreshToken",
    "perimeterxIdentifiers",
    "cf-browser-verification",
    "Attention Required! | Cloudflare",
    "Just a moment...",
    "Enable JavaScript and cookies to continue",
    "ddos-guard",
    "Sucuri WebSite Firewall",
    "Request unsuccessful. Incapsula",
)

# URLs that answer 200 for *any* input and therefore prove nothing.
NON_DISCRIMINATING = (
    re.compile(r"^https?://[^/]+/?$"),
    re.compile(r"[?&](q|search|query|filter|keyword|inname|name_contains)=", re.I),
    re.compile(r"/search(/|\?|$)", re.I),
    re.compile(r"#@"),
    re.compile(r"/login(/|\?|$)", re.I),
    re.compile(r"/signin(/|\?|$)", re.I),
    re.compile(r"/signup(/|\?|$)", re.I),
    re.compile(r"/register(/|\?|$)", re.I),
    re.compile(r"/404(/|\?|$)"),
)

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
OG_RE = re.compile(r'<meta[^>]+(?:property|name)=["\']og:(\w+)["\'][^>]+content=["\']([^"\']*)["\']', re.I)
DESC_RE = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)["\']', re.I)
# Bounded quantifiers: unbounded classes backtrack quadratically on the
# multi-megabyte minified pages some sites return (measured: 1.2s per page).
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}")


@dataclass
class Verdict:
    status: str
    confidence: float
    reason: str

    @property
    def found(self) -> bool:
        return self.status == FOUND


def _as_list(value) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v]
    return []


def looks_blocked(body: str) -> bool:
    if not body:
        return False
    sample = body[:6000]
    return any(marker in sample for marker in WAF_MARKERS)


PARKED_MARKERS = (
    "this domain is for sale", "buy this domain", "domain may be for sale",
    "hugedomains", "afternic", "sedo.com", "domain parking", "parked free",
    "this domain has expired", "website is for sale",
)


def looks_parked(body: str) -> bool:
    if not body:
        return False
    sample = body[:4000].lower()
    return any(marker in sample for marker in PARKED_MARKERS)


def looks_like_stub(body: str) -> bool:
    """Tiny page whose only job is to redirect somewhere else."""
    if not body or len(body) > 3000:
        return False
    sample = body.lower()
    return (
        "http-equiv=\"refresh\"" in sample
        or "http-equiv='refresh'" in sample
        or "window.location" in sample
        or "location.href" in sample
        or "location.replace" in sample
    )


def non_discriminating(url: str, needle: str = "") -> bool:
    """A 200 on the site root / a search page says nothing about the account."""
    if not url:
        return False
    for pattern in NON_DISCRIMINATING:
        if pattern.search(url):
            return True
    # the identifier vanished from the URL -> we got bounced somewhere generic
    if needle and needle.lower() not in url.lower() and "?" not in url:
        return True
    return False


def classify(defn: dict, status: int, body: str, final_url: str,
             needle: str = "", platform: str = "") -> Verdict:
    """Turn a raw HTTP response into found / not_found / unknown / blocked."""
    check = defn.get("check") or {}
    mode = check.get("mode") or "status"
    body_unescaped = html.unescape(body or "")

    # --- provider-availability gate (MailAccess R3) -------------------------
    if status == 429 or 500 <= status <= 599:
        return Verdict(UNKNOWN, 0.0, f"provider_unavailable:{status}")
    if looks_blocked(body_unescaped):
        return Verdict(BLOCKED, 0.0, "waf_challenge")
    if looks_parked(body_unescaped):
        return Verdict(UNKNOWN, 0.0, "parked_domain")
    if looks_like_stub(body_unescaped):
        return Verdict(UNKNOWN, 0.0, "redirect_stub")

    # --- two independent markers (WhatsMyName / MailAccess) -----------------
    if mode == "two_marker":
        e_code = check.get("exists", {}).get("code")
        m_code = check.get("missing", {}).get("code")
        e_string = str(check.get("exists", {}).get("text") or "")
        m_string = str(check.get("missing", {}).get("text") or "")

        e_present = (e_code is None or status == e_code) and (not e_string or e_string in body_unescaped)
        m_present = (m_code is None or status == m_code) and (not m_string or m_string in body_unescaped)

        # collision guard: absence marker strictly more specific than presence
        if e_present and m_present and e_string and e_string in m_string and e_string != m_string:
            return Verdict(NOT_FOUND, 0.92, "two_marker_absence_wins")
        # JSON APIs often enumerate both enum values ("sign_in"/"sign_up"):
        # both markers present in a small JSON payload proves nothing.
        if e_present and m_present:
            stripped = body_unescaped.lstrip()
            if stripped.startswith(("{", "[")) and len(body_unescaped) < 4000:
                return Verdict(UNKNOWN, 0.0, "ambiguous_markers")
        if e_present:
            conf = 0.96 if e_string else 0.86
            if non_discriminating(final_url):
                return Verdict(UNKNOWN, 0.2, "non_discriminating_url")
            return Verdict(FOUND, conf, "two_marker_present")
        if m_present:
            return Verdict(NOT_FOUND, 0.95 if m_string else 0.85, "two_marker_absent")
        if not body_unescaped.strip():
            return Verdict(UNKNOWN, 0.0, "empty_body")
        return Verdict(UNKNOWN, 0.0, "no_marker")

    # --- status code --------------------------------------------------------
    if mode == "status":
        missing_codes = check.get("missing", {}).get("code")
        codes = missing_codes if isinstance(missing_codes, (list, tuple)) else [missing_codes]
        codes = [c for c in codes if isinstance(c, int)]
        if codes and status in codes:
            return Verdict(NOT_FOUND, 0.9, f"status_{status}_missing")
        if 200 <= status < 300:
            min_bytes = check.get("min_bytes")
            if isinstance(min_bytes, int) and len(body_unescaped) < min_bytes:
                return Verdict(UNKNOWN, 0.1, "body_too_small")
            if non_discriminating(final_url):
                return Verdict(UNKNOWN, 0.2, "non_discriminating_url")
            if not _echoes(body_unescaped, final_url, needle):
                return Verdict(UNKNOWN, 0.25, "identifier_not_echoed")
            return Verdict(FOUND, 0.78, f"status_{status}")
        if 300 <= status < 400:
            if defn.get("follow_redirects") is False:
                return Verdict(FOUND, 0.7, f"redirect_{status}")
            return Verdict(UNKNOWN, 0.2, f"redirect_{status}")
        if status in (401, 403):
            return Verdict(BLOCKED, 0.0, f"auth_{status}")
        return Verdict(NOT_FOUND, 0.8, f"status_{status}")

    # --- message in body ----------------------------------------------------
    if mode == "message":
        errors = _as_list(check.get("missing", {}).get("text"))
        positives = _as_list(check.get("exists", {}).get("text"))
        if not body_unescaped.strip():
            return Verdict(UNKNOWN, 0.0, "empty_body")
        if non_discriminating(final_url):
            return Verdict(UNKNOWN, 0.2, "non_discriminating_url")
        if positives:
            if all(p in body_unescaped for p in positives):
                return Verdict(FOUND, 0.9, "positive_marker")
            return Verdict(NOT_FOUND, 0.8, "positive_marker_absent")
        if errors and any(e in body_unescaped for e in errors):
            return Verdict(NOT_FOUND, 0.88, "error_marker")
        if not _echoes(body_unescaped, final_url, needle):
            return Verdict(UNKNOWN, 0.25, "identifier_not_echoed")
        return Verdict(FOUND, 0.8, "no_error_marker")

    # --- redirect -----------------------------------------------------------
    if mode == "redirect":
        if 200 <= status < 300:
            if not _echoes(body_unescaped, final_url, needle):
                return Verdict(UNKNOWN, 0.25, "identifier_not_echoed")
            return Verdict(FOUND, 0.8, "redirect_target_ok")
        return Verdict(NOT_FOUND, 0.75, f"redirect_{status}")

    return Verdict(UNKNOWN, 0.0, "unknown_mode")


def _echoes(body: str, final_url: str, needle: str) -> bool:
    """A real profile mentions the identifier in its *content*, not just its path.

    Bitchute (and friends) echo the requested path in a meta tag for every
    input, so a naive substring test turns every 200 into a false positive.
    """
    if not needle:
        return True
    needle = needle.lower()
    body_low = body.lower()
    if needle not in body_low:
        return False
    stripped = body_low.lstrip()
    if stripped.startswith(("{", "[")):
        return True  # JSON payloads mention the id once, and that's enough
    title = TITLE_RE.search(body)
    if title and needle in html.unescape(title.group(1)).lower():
        return True
    for match in OG_RE.finditer(body[:60_000]):
        if match.group(1).lower() in ("title", "site_name"):
            if needle in html.unescape(match.group(2)).lower():
                return True
    return False


def extract_profile(body: str) -> dict:
    """Cheap, dependency-free profile enrichment (name / avatar / bio / emails)."""
    if not body:
        return {}
    out: dict = {}
    title = TITLE_RE.search(body)
    if title:
        text = html.unescape(re.sub(r"\s+", " ", title.group(1))).strip()
        if text:
            out["title"] = text[:180]
    for key, value in OG_RE.findall(body[:200_000]):
        key = key.lower()
        if key in ("title", "description", "image", "site_name", "url") and value.strip():
            out[f"og_{key}"] = html.unescape(value.strip())[:400]
    desc = DESC_RE.search(body[:200_000])
    if desc:
        out.setdefault("description", html.unescape(desc.group(1)).strip()[:400])
    if "@" in body:
        emails = list(dict.fromkeys(EMAIL_RE.findall(body[:120_000])))[:8]
    else:
        emails = []
    if emails:
        out["emails"] = emails
    return out


def title_name(title: str) -> str | None:
    """Best-effort human name from a profile <title>."""
    if not title:
        return None
    for sep in (" | ", " - ", " · ", " — ", " – ", " :: "):
        if sep in title:
            head = title.split(sep)[0].strip()
            if 1 < len(head) < 60:
                return head
    return None
