"""Build the unified MIRSAD site database from every upstream source.

Sources
-------
* sherlock        -> sherlock_project/resources/data.json      (username, status/message/redirect)
* whatsmyName     -> wmn-data.json                             (username, two-marker)
* mailaccess      -> data/mailaccess_sites.json                (username + email, two-marker)
* blackbird       -> data/email-data.json                      (email, wmn-derived)
* zehef / eyes / holehe -> hand-written defs in tools/curated_email.py

Output: mirsad/data/sites.json  (one list, one schema)

Run:  python tools/build_data.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from curated_email import CURATED  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RESEARCH = ROOT / "_research"
OUT = ROOT / "mirsad" / "data" / "sites.json"

# Sites people actually care about -> tier 1 (fast scan).
CORE = {
    "github", "twitter", "x", "instagram", "facebook", "reddit", "tiktok",
    "youtube", "telegram", "pinterest", "snapchat", "linkedin", "tumblr",
    "medium", "twitch", "steam", "spotify", "soundcloud", "gitlab",
    "bitbucket", "keybase", "hackernews", "devto", "stackoverflow",
    "behance", "dribbble", "vk", "ok", "flickr", "imgur", "patreon",
    "discord", "mastodon", "threads", "bluesky", "quora", "aboutme",
    "gravatar", "duolingo", "strava", "chess", "codepen", "replit",
    "hackerrank", "leetcode", "kaggle", "npm", "pypi", "dockerhub",
    "producthunt", "angelco", "crunchbase", "trello", "notion", "figma",
    "vimeo", "dailymotion", "mixcloud", "bandcamp", "lastfm", "deezer",
    "tidal", "letterboxd", "goodreads", "myanimelist", "roblox", "epicgames",
    "xbox", "playstation", "nintendo", "battlenet", "origin", "uplay",
    "venmo", "cashapp", "paypal", "ebay", "etsy", "amazon",
    "airbnb", "booking", "tripadvisor", "yelp", "foursquare", "swarm",
    "periscope", "clubhouse", "rumble", "odysee", "bitchute", "gab",
    "parler", "truthsocial", "minds", "weibo", "wechat", "line",
    "kakao", "naver", "zalo", "viber", "signal", "wire", "element",
    "matrix", "rocketchat", "slack", "zoom", "skype", "teams",
    "wordpress", "blogger", "wix", "squarespace",
    "weebly", "jimdo", "webnode", "carrd", "linktree", "beacons",
    "bitly", "tinyurl", "pastebin", "ghostbin", "hastebin", "rentry",
    "jsfiddle", "codesandbox", "glitch", "vercel", "netlify",
    "heroku", "railway", "render", "fly", "supabase", "firebase",
    "hackerone", "bugcrowd", "intigriti", "yeswehack", "synack",
    "tryhackme", "hackthebox", "vulnhub", "pentesterlab", "portswigger",
    "shodan", "censys", "virustotal", "urlscan", "securitytrails",
    "hunter", "haveibeenpwned", "dehashed", "leakcheck", "snusbase",
    "intelx", "pgp", "keyserver",
}


def slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower())
    return value.strip("-") or "unknown"


def host_of(url: str) -> str:
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    try:
        host = urlparse(url).netloc.lower()
    except ValueError:
        return ""
    return host.removeprefix("www.")


def ph(value: str) -> str:
    """Normalise every placeholder dialect to ``{}``."""
    if not value:
        return ""
    for token in ("{account}", "{username}", "{user}", "{email}"):
        value = value.replace(token, "{}")
    return value


# Only locale/device prefixes are safe to collapse. "api." and "auth." often
# host a *different* check (api.github.com/gists is not github.com), so they
# stay separate and are merged later by the report's base-domain dedupe.
SUBDOMAIN_PREFIXES = {"www", "m", "en", "fr", "de", "es", "it", "pt", "ru", "ja",
                      "mobile", "beta", "old", "new"}
DOMAIN_ALIASES = {
    "twitter.com": "x.com", "threads.net": "threads.com", "pscp.tv": "periscope.tv",
    "youtu.be": "youtube.com", "t.co": "x.com",
}


def merge_domain(domain: str) -> str:
    """www.github.com / api.github.com / en.gravatar.com -> github.com / gravatar.com."""
    parts = [p for p in (domain or "").lower().split(".") if p]
    if len(parts) > 2 and parts[0] in SUBDOMAIN_PREFIXES:
        parts = parts[1:]
    base = ".".join(parts)
    return DOMAIN_ALIASES.get(base, base)


def norm_cat(cat: str | None) -> str:
    if not cat:
        return "misc"
    cat = str(cat).strip().lower().replace("xx nsfw xx", "nsfw")
    aliases = {
        "social_media": "social", "social media": "social", "programing": "coding",
        "programming": "coding", "tech": "coding", "images": "art", "video": "media",
        "music": "media", "news": "media", "political": "misc", "health": "misc",
        "real_estate": "business", "crowfunding": "finance", "crm": "business",
        "company": "business", "products": "shopping", "product": "shopping",
        "software": "coding", "transport": "misc", "sport": "hobby",
        "learning": "education", "jobs": "business", "medical": "misc",
        "payment": "finance", "porn": "nsfw", "adult": "nsfw", "dating": "social",
    }
    return aliases.get(cat, cat)


def base_record(**kw) -> dict:
    rec = {
        "id": "", "name": "", "domain": "", "category": "misc",
        "kind": "username", "url": "", "probe": "", "method": "GET",
        "headers": {}, "payload": None, "pre_check": None, "follow_redirects": True,
        "check": {}, "regex": None, "nsfw": False, "sources": [],
        "tier": 3, "flow": None, "disabled": False, "note": None,
        "popularity": 0,
    }
    rec.update(kw)
    return rec


def quality(rec: dict) -> int:
    """Higher = better definition. Used when merging duplicates."""
    check = rec.get("check") or {}
    score = 0
    if check.get("exists", {}).get("text") and check.get("missing", {}).get("text"):
        score += 100  # two-marker, most reliable
    elif check.get("exists", {}).get("text") or check.get("missing", {}).get("text"):
        score += 60
    if check.get("mode") == "status":
        score += 30
    if check.get("missing", {}).get("code"):
        score += 20
    if rec.get("probe") and rec.get("probe") != rec.get("url"):
        score += 5
    if rec.get("payload"):
        score += 3
    if rec.get("handler"):
        score += 150  # hand-verified techniques beat scraped markers
    if rec.get("disabled"):
        score -= 50
    score += len(rec.get("sources") or [])
    return score


def load_sherlock() -> list[dict]:
    path = RESEARCH / "sherlock" / "sherlock_project" / "resources" / "data.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for name, d in data.items():
        if not isinstance(d, dict) or name.startswith("$"):
            continue
        url = d.get("url") or ""
        if "{}" not in url:
            continue
        etype = d.get("errorType")
        etypes = etype if isinstance(etype, list) else [etype] if etype else []
        check: dict = {}
        if "message" in etypes:
            check = {"mode": "message", "missing": {"text": d.get("errorMsg")}}
        elif "status_code" in etypes:
            check = {"mode": "status", "missing": {"code": d.get("errorCode")}}
        elif "response_url" in etypes:
            check = {"mode": "redirect"}
        else:
            check = {"mode": "status"}
        rec = base_record(
            id=slug(name), name=name, domain=host_of(d.get("urlMain") or url),
            category=norm_cat(d.get("cat")), kind="username", url=url,
            probe=d.get("urlProbe") or url, method=(d.get("request_method") or "GET").upper(),
            headers=d.get("headers") or {}, payload=d.get("request_payload"),
            check=check, regex=d.get("regexCheck"),
            nsfw=bool(d.get("isNSFW")), sources=["sherlock"],
        )
        out.append(rec)
    return out


def load_wmn() -> list[dict]:
    path = RESEARCH / "WhatsMyName" / "wmn-data.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for d in data.get("sites", []):
        url = ph(d.get("uri_check") or "")
        if "{}" not in url:
            continue
        check = {
            "mode": "two_marker",
            "exists": {"code": d.get("e_code"), "text": d.get("e_string") or ""},
            "missing": {"code": d.get("m_code"), "text": d.get("m_string") or ""},
        }
        cat = norm_cat(d.get("cat"))
        rec = base_record(
            id=slug(d.get("name", "")), name=d.get("name", ""),
            domain=host_of(url), category=cat, kind="username", url=url, probe=url,
            method=(d.get("request_method") or "GET").upper(),
            headers=d.get("headers") or {}, payload=d.get("request_payload"),
            check=check, nsfw=cat == "nsfw", sources=["whatsmyname"],
        )
        out.append(rec)
    return out


def load_mailaccess() -> tuple[list[dict], list[dict]]:
    path = RESEARCH / "MailAccess" / "data" / "mailaccess_sites.json"
    if not path.exists():
        return [], []
    data = json.loads(path.read_text(encoding="utf-8")).get("sites", {})
    users, emails = [], []
    for key, d in data.items():
        uri = ph(d.get("uri_check") or d.get("url") or "")
        if not uri:
            continue
        kind = "email" if d.get("check_type") == "email-existence" else "username"
        if kind == "username" and "{}" not in uri:
            continue
        check: dict = {}
        if d.get("e_code") is not None and d.get("m_code") is not None:
            check = {
                "mode": "two_marker",
                "exists": {"code": d.get("e_code"), "text": d.get("e_string") or ""},
                "missing": {"code": d.get("m_code"), "text": d.get("m_string") or ""},
            }
        elif d.get("checkType") == "status_code" or d.get("check_type") == "status_code":
            check = {"mode": "status", "min_bytes": d.get("min_response_bytes")}
        else:
            check = {
                "mode": "message",
                "exists": {"text": d.get("presenseStrs") or d.get("presenceStrs")},
                "missing": {"text": d.get("absenceStrs")},
            }
        rec = base_record(
            id=slug(d.get("id") or key), name=d.get("name") or key,
            domain=d.get("domain") or host_of(uri), category=norm_cat(d.get("category")),
            kind=kind, url=ph(d.get("url")) or uri,
            probe=uri, method=(d.get("requestMethod") or d.get("method") or "GET").upper(),
            headers=d.get("headers") or {}, payload=d.get("requestPayload"),
            pre_check=d.get("pre_check"), follow_redirects=d.get("follow_redirects", True), check=check,
            nsfw=norm_cat(d.get("category")) == "nsfw", sources=["mailaccess"],
            flow=d.get("flow"), disabled=bool(d.get("disabled")),
            note=d.get("disabled_reason") if d.get("disabled") else None,
        )
        (emails if kind == "email" else users).append(rec)
    return users, emails


def load_blackbird_email() -> list[dict]:
    path = RESEARCH / "blackbird" / "data" / "email-data.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for d in data.get("sites", []):
        if not d.get("is_email_only"):
            continue
        url = (d.get("uri_check") or "").replace("{account}", "{}")
        if "{}" not in url:
            continue
        out.append(base_record(
            id=slug(d.get("name", "")), name=d.get("name", ""), domain=host_of(url),
            category=norm_cat(d.get("cat")), kind="email", url=url, probe=url,
            method=(d.get("request_method") or "GET").upper(),
            headers=d.get("headers") or {},
            check={"mode": "two_marker",
                   "exists": {"code": d.get("e_code"), "text": d.get("e_string") or ""},
                   "missing": {"code": d.get("m_code"), "text": d.get("m_string") or ""}},
            nsfw=norm_cat(d.get("cat")) == "nsfw", sources=["blackbird"],
        ))
    return out


# Definitions verified broken during development (they answer "taken" for any
# address, or need a session we can't bootstrap). Kept visible, never probed.
VERIFIED_BROKEN = {
    "etsy.com": "returns a placeholder user for any address (checked 2026-10)",
    "figma.com": "lists sign_in for any address (checked 2026-10)",
    "replit.com": "exists:true for any address (checked 2026-10)",
}


def merge(records: list[dict]) -> list[dict]:
    merged: dict[tuple[str, str], dict] = {}
    for rec in records:
        if not rec["domain"] or not rec["probe"]:
            continue
        if rec["domain"] in VERIFIED_BROKEN:
            rec["disabled"] = True
            rec["note"] = VERIFIED_BROKEN[rec["domain"]]
        key = (rec["kind"], merge_domain(rec["domain"]))
        cur = merged.get(key)
        if cur is None:
            merged[key] = rec
            continue
        # keep the higher-quality definition, union provenance
        winner = rec if quality(rec) > quality(cur) else cur
        loser = cur if winner is rec else rec
        winner["sources"] = sorted(set(winner["sources"]) | set(loser["sources"]))
        if loser.get("disabled") and not winner.get("disabled"):
            winner["disabled"] = True
        # keep the most specific category, not the generic "misc"
        if winner.get("category") in ("misc", None) and loser.get("category") not in ("misc", None):
            winner["category"] = loser["category"]
        if not winner.get("regex") and loser.get("regex"):
            winner["regex"] = loser["regex"]
        merged[key] = winner
    return list(merged.values())


NAME_OVERRIDES = {
    "twitchtracker.com": "TwitchTracker",
    "socialblade.com": "SocialBlade",
    "similarweb.com": "SimilarWeb",
}


def tier_for(rec: dict) -> int:
    ident = {rec["id"], slug(rec["name"]), slug(rec["domain"].split(".")[0])}
    if ident & CORE:
        return 1
    check = rec.get("check") or {}
    strong = bool(check.get("exists", {}).get("text") or check.get("missing", {}).get("text"))
    if strong and rec["category"] not in ("misc", "nsfw"):
        return 2
    return 3


def main() -> None:
    if not RESEARCH.exists():
        raise SystemExit(
            "The upstream sources are missing.\n"
            "Run: python tools/fetch_sources.py   (clones the 11 projects into _research/)\n"
            "then: python tools/build_data.py"
        )
    sherlock = load_sherlock()
    wmn = load_wmn()
    ma_users, ma_emails = load_mailaccess()
    bb_email = load_blackbird_email()

    curated = [base_record(**c) for c in CURATED]
    users = merge(sherlock + wmn + ma_users)
    emails = merge(ma_emails + bb_email + curated)

    for rec in users + emails:
        rec["tier"] = tier_for(rec)
        override = NAME_OVERRIDES.get(rec["domain"])
        if override:
            rec["name"] = override

    # drop dead entries, keep disabled ones but flagged
    users.sort(key=lambda r: (r["tier"], r["name"].lower()))
    emails.sort(key=lambda r: r["name"].lower())

    payload = {
        "_meta": {
            "schema": 1,
            "built_from": {
                "sherlock": len(sherlock), "whatsmyname": len(wmn),
                "mailaccess_username": len(ma_users), "mailaccess_email": len(ma_emails),
                "blackbird_email": len(bb_email), "curated_email": len(CURATED),
            },
            "username_sites": len(users), "email_sites": len(emails),
        },
        "sites": users + emails,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    print(json.dumps(payload["_meta"], indent=2))
    tiers = {1: 0, 2: 0, 3: 0}
    for rec in users:
        tiers[rec["tier"]] += 1
    print("username tiers:", tiers)
    print("output:", OUT, f"{OUT.stat().st_size/1024:.0f} KB")


if __name__ == "__main__":
    main()
