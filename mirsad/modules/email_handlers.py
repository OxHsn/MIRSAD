"""Bespoke email-existence handlers.

Some services don't answer with a marker in HTML — they answer with JSON
logic, a CSRF-protected form, or a two-step token dance. These handlers
reproduce the technique of holehe / Zehef / Eyes against each such service
and return the same normalised verdict as a declarative probe.
"""

from __future__ import annotations

import hashlib
import json
import re

from ..core.detect import looks_blocked
from ..core.models import BLOCKED, FOUND, NOT_FOUND, UNKNOWN
from .base import handler


def _r(status: str, confidence: float, reason: str, url: str = "", **data) -> dict:
    return {"status": status, "confidence": confidence, "reason": reason, "url": url, "data": data}


def _inputs(body: str) -> dict:
    """Extract name/value pairs from the first form on a page."""
    out: dict[str, str] = {}
    for tag in re.findall(r"<input\b[^>]*>", body, re.I):
        name = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        value = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
        if name:
            out[name.group(1)] = value.group(1) if value else ""
    return out


def _json(resp):
    try:
        return json.loads(resp.text)
    except Exception:
        return None


# --------------------------------------------------------------------- Adobe
@handler("adobe")
async def adobe(fetcher, site, email):
    resp = await fetcher.post(
        "https://auth.services.adobe.com/signin/v2/users/accounts",
        payload={"username": email, "usernameType": "EMAIL"},
        headers={"x-ims-clientid": "homepage_milo", "content-type": "application/json"},
    )
    if not resp.ok:
        return _r(UNKNOWN, 0.0, resp.error or "request_failed")
    data = _json(resp)
    if isinstance(data, list) and data:
        methods = data[0].get("authenticationMethods")
        if methods:
            return _r(FOUND, 0.92, "adobe_auth_methods", "https://account.adobe.com/",
                      name=(data[0].get("displayName") or ""))
        return _r(NOT_FOUND, 0.9, "adobe_no_methods")
    if isinstance(data, dict) and data.get("errorCode"):
        return _r(UNKNOWN, 0.0, f"adobe_error:{data.get('errorCode')}")
    return _r(UNKNOWN, 0.0, "adobe_unexpected_payload")


# -------------------------------------------------------------------- Amazon
@handler("amazon")
async def amazon(fetcher, site, email):
    signin = "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&"
    page = await fetcher.get(signin)
    if not page.ok:
        return _r(UNKNOWN, 0.0, page.error or "request_failed")
    form = _inputs(page.text)
    form["email"] = email
    resp = await fetcher.post("https://www.amazon.com/ap/signin/", form=form)
    if not resp.ok:
        return _r(UNKNOWN, 0.0, resp.error or "request_failed")
    body = resp.text
    if looks_blocked(body):
        return _r(BLOCKED, 0.0, "waf_challenge")
    if "auth-password-missing-alert" in body or 'name="password"' in body or "ap_password" in body:
        return _r(FOUND, 0.85, "amazon_password_prompt", "https://www.amazon.com/")
    if "We cannot find an account" in body or "auth-error-message-box" in body or "cannot find an account" in body.lower():
        return _r(NOT_FOUND, 0.85, "amazon_no_account")
    return _r(UNKNOWN, 0.0, "amazon_inconclusive")


# ------------------------------------------------------------------- BandLab
@handler("bandlab")
async def bandlab(fetcher, site, email):
    resp = await fetcher.get(f"https://www.bandlab.com/api/v1.3/validation/user?email={email}")
    data = _json(resp)
    if not isinstance(data, dict):
        return _r(UNKNOWN, 0.0, "bandlab_no_json")
    if data.get("isValid") and data.get("isAvailable") is False:
        return _r(FOUND, 0.9, "bandlab_taken", "https://www.bandlab.com/")
    if data.get("isAvailable") is True:
        return _r(NOT_FOUND, 0.88, "bandlab_available")
    return _r(UNKNOWN, 0.0, "bandlab_inconclusive")


# --------------------------------------------------------------------- Chess
@handler("chess")
async def chess(fetcher, site, email):
    resp = await fetcher.post(f"https://www.chess.com/callback/email/available?email={email}")
    data = _json(resp)
    if not isinstance(data, dict):
        return _r(UNKNOWN, 0.0, "chess_no_json")
    if data.get("isEmailAvailable") is False:
        return _r(FOUND, 0.9, "chess_taken", "https://www.chess.com/")
    if data.get("isEmailAvailable") is True:
        return _r(NOT_FOUND, 0.88, "chess_available")
    return _r(UNKNOWN, 0.0, "chess_inconclusive")


# -------------------------------------------------------------------- Deezer
@handler("deezer")
async def deezer(fetcher, site, email):
    boot = await fetcher.post(
        "https://www.deezer.com/ajax/gw-light.php?method=deezer.getUserData&input=3&api_version=1.0&api_token=&cid="
    )
    data = _json(boot)
    token = None
    if isinstance(data, dict):
        token = (data.get("results") or {}).get("checkForm")
    if not token:
        return _r(UNKNOWN, 0.0, "deezer_no_token")
    resp = await fetcher.post(
        f"https://www.deezer.com/ajax/gw-light.php?method=deezer.emailCheck&input=3&api_version=1.0&api_token={token}",
        payload=json.dumps({"EMAIL": email}),
        headers={"Content-Type": "application/json"},
    )
    data = _json(resp)
    result = (data or {}).get("results") or {}
    if result.get("availability") is False:
        return _r(FOUND, 0.9, "deezer_taken", "https://www.deezer.com/")
    if result.get("availability") is True:
        return _r(NOT_FOUND, 0.88, "deezer_available")
    return _r(UNKNOWN, 0.0, "deezer_inconclusive")


# ------------------------------------------------------------------ Duolingo
@handler("duolingo")
async def duolingo(fetcher, site, email):
    resp = await fetcher.get(f"https://www.duolingo.com/2017-06-30/users?email={email}")
    data = _json(resp)
    if not isinstance(data, dict):
        return _r(UNKNOWN, 0.0, "duolingo_no_json")
    users = data.get("users")
    if users:
        first = users[0] if isinstance(users[0], dict) else {}
        # anonymous/default user object means "no account for this address"
        if not first.get("username") or int(first.get("id") or 0) <= 0:
            return _r(NOT_FOUND, 0.88, "duolingo_anonymous_user")
        return _r(FOUND, 0.9, "duolingo_user", f"https://www.duolingo.com/profile/{first.get('username', '')}",
                  username=first.get("username"), name=first.get("name"), picture=first.get("picture"))
    if users == []:
        return _r(NOT_FOUND, 0.88, "duolingo_empty")
    return _r(UNKNOWN, 0.0, "duolingo_inconclusive")


# --------------------------------------------------------------- GitHub email
@handler("github_email")
async def github_email(fetcher, site, email):
    headers = {"Accept": "application/vnd.github+json"}
    if fetcher.settings.github_token:
        headers["Authorization"] = f"Bearer {fetcher.settings.github_token}"
    # commit search is exact; the user-search endpoint matches fuzzily on the
    # local part ("test@example.com" returns every user called "test").
    resp = await fetcher.get(
        f"https://api.github.com/search/commits?q=author-email:{email}&per_page=20", headers=headers
    )
    data = _json(resp)
    if not isinstance(data, dict):
        return _r(UNKNOWN, 0.0, "github_no_json")
    if data.get("message") and "rate limit" in str(data.get("message")).lower():
        return _r(UNKNOWN, 0.0, "github_rate_limited")
    items = data.get("items") or []
    if not items:
        return _r(NOT_FOUND, 0.85, "github_no_commits")
    authors = {}
    for item in items:
        author = item.get("author") or {}
        if author.get("login"):
            authors[author["login"]] = author.get("html_url", "")
    first = next(iter(authors.items()), (None, ""))
    return _r(FOUND, 0.9, "github_commit_email",
              first[1] or f"https://github.com/{first[0]}" if first[0] else "",
              username=first[0], usernames=sorted(authors)[:10],
              commits=data.get("total_count"))


# ------------------------------------------------------------------- Gravatar
@handler("gravatar")
async def gravatar(fetcher, site, email):
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    resp = await fetcher.get(f"https://en.gravatar.com/{digest}.json")
    if resp.status == 404:
        return _r(NOT_FOUND, 0.9, "gravatar_404")
    data = _json(resp)
    if not resp.ok or not isinstance(data, dict):
        return _r(UNKNOWN, 0.0, "gravatar_no_json")
    entry = (data.get("entry") or [{}])[0]
    name = None
    for item in entry.get("name", {}).values() if isinstance(entry.get("name"), dict) else []:
        if item:
            name = item
            break
    return _r(FOUND, 0.95, "gravatar_profile",
              f"https://gravatar.com/{digest}",
              name=name, avatar=entry.get("thumbnailUrl"),
              emails=[e.get("value") for e in entry.get("emails", []) if e.get("value")],
              accounts=[a.get("url") for a in entry.get("accounts", []) if a.get("url")])


# ---------------------------------------------------------------------- Imgur
@handler("imgur")
async def imgur(fetcher, site, email):
    resp = await fetcher.post("https://imgur.com/signin/ajax_email_available", form={"email": email})
    data = _json(resp)
    payload = (data or {}).get("data") or {}
    if payload.get("available") is False:
        return _r(FOUND, 0.88, "imgur_taken", "https://imgur.com/")
    if payload.get("available") is True:
        return _r(NOT_FOUND, 0.85, "imgur_available")
    return _r(UNKNOWN, 0.0, "imgur_inconclusive")


# ------------------------------------------------------------------ Instagram
@handler("instagram")
async def instagram(fetcher, site, email):
    boot = await fetcher.get("https://www.instagram.com/accounts/emailsignup/")
    csrf = (boot.cookies or {}).get("csrftoken")
    if not csrf:
        match = re.search(r'"csrf_token":"([^"]+)"', boot.text or "")
        csrf = match.group(1) if match else None
    if not csrf:
        return _r(UNKNOWN, 0.0, "instagram_no_csrf")
    resp = await fetcher.post(
        "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/",
        form={"email": email, "first_name": "", "username": "", "opt_into_one_tap": "false"},
        headers={"x-csrftoken": csrf, "Referer": "https://www.instagram.com/accounts/emailsignup/",
                 "X-Requested-With": "XMLHttpRequest"},
    )
    data = _json(resp)
    if not isinstance(data, dict):
        return _r(UNKNOWN, 0.0, "instagram_no_json")
    errors = (data.get("errors") or {}).get("email") or []
    code = errors[0].get("code") if errors and isinstance(errors[0], dict) else None
    if code == "email_is_taken":
        return _r(FOUND, 0.9, "instagram_taken", "https://www.instagram.com/")
    if code in ("invalid_email", "email_sharing_disabled"):
        return _r(UNKNOWN, 0.0, f"instagram_{code}")
    return _r(NOT_FOUND, 0.8, "instagram_available")


# ------------------------------------------------------------------ Pinterest
@handler("pinterest")
async def pinterest(fetcher, site, email):
    payload = json.dumps({"options": {"email": email}, "context": {}})
    resp = await fetcher.request(
        f"https://www.pinterest.com/resource/EmailExistsResource/get/?source_url=%2F&data={payload}",
        method="GET",
        headers={"Accept": "application/json"},
    )
    data = _json(resp)
    if not isinstance(data, dict):
        return _r(UNKNOWN, 0.0, "pinterest_no_json")
    if data.get("resource_response", {}).get("data"):
        return _r(FOUND, 0.88, "pinterest_exists", "https://www.pinterest.com/")
    return _r(NOT_FOUND, 0.8, "pinterest_absent")


# --------------------------------------------------------------------- Picsart
@handler("picsart")
async def picsart(fetcher, site, email):
    resp = await fetcher.get(f"https://api.picsart.com/users/email/existence?email_encoded=1&emails={email}")
    data = _json(resp)
    if not isinstance(data, dict):
        return _r(UNKNOWN, 0.0, "picsart_no_json")
    if data.get("status") != "success":
        return _r(UNKNOWN, 0.0, "picsart_ratelimit")
    if data.get("response") is True:
        return _r(FOUND, 0.88, "picsart_taken", "https://picsart.com/")
    return _r(NOT_FOUND, 0.85, "picsart_available")


# -------------------------------------------------------------------- Pornhub
@handler("pornhub")
async def pornhub(fetcher, site, email):
    page = await fetcher.get("https://www.pornhub.com/signup")
    token = _inputs(page.text).get("token")
    if not token:
        return _r(UNKNOWN, 0.0, "pornhub_no_token")
    resp = await fetcher.post(
        f"https://www.pornhub.com/user/create_account_check?token={token}",
        form={"check_what": "email", "email": email},
        headers={"Referer": "https://www.pornhub.com/signup"},
    )
    data = _json(resp)
    value = (data or {}).get("email")
    if value == "create_account_failed":
        return _r(FOUND, 0.9, "pornhub_taken", "https://www.pornhub.com/")
    if value == "create_account_passed":
        return _r(NOT_FOUND, 0.88, "pornhub_available")
    return _r(UNKNOWN, 0.0, "pornhub_inconclusive")


# --------------------------------------------------------------------- Strava
@handler("strava")
async def strava(fetcher, site, email):
    resp = await fetcher.get(f"https://www.strava.com/frontend/athletes/email_unique?email={email}")
    body = (resp.text or "").strip().lower()
    if "false" in body:
        return _r(FOUND, 0.85, "strava_taken", "https://www.strava.com/")
    if "true" in body:
        return _r(NOT_FOUND, 0.85, "strava_available")
    return _r(UNKNOWN, 0.0, "strava_inconclusive")


# ------------------------------------------------------------------- Twitter/X
@handler("twitter_email")
async def twitter_email(fetcher, site, email):
    resp = await fetcher.get(f"https://api.twitter.com/i/users/email_available.json?email={email}")
    data = _json(resp)
    if not isinstance(data, dict):
        return _r(UNKNOWN, 0.0, "twitter_no_json")
    if data.get("taken") is True:
        return _r(FOUND, 0.9, "twitter_taken", "https://x.com/")
    if data.get("taken") is False:
        return _r(NOT_FOUND, 0.88, "twitter_available")
    return _r(UNKNOWN, 0.0, "twitter_inconclusive")


# ------------------------------------------------------------------ ProtonMail
@handler("protonmail")
async def protonmail(fetcher, site, email):
    """No account API without a session -> use the public PGP keyserver as oracle."""
    resp = await fetcher.get(f"https://api.protonmail.ch/pks/lookup?op=index&search={email}")
    if not resp.ok:
        return _r(UNKNOWN, 0.0, "proton_keyserver_unreachable")
    match = re.search(r"\b(\d{10})\b", resp.text or "")
    if match:
        import datetime as _dt
        created = _dt.datetime.fromtimestamp(int(match.group(1))).strftime("%Y-%m-%d")
        return _r(FOUND, 0.75, "proton_pgp_key", "https://account.proton.me/", created=created)
    if "No key found" in (resp.text or "") or resp.status == 404:
        return _r(UNKNOWN, 0.0, "proton_no_public_key")
    return _r(UNKNOWN, 0.0, "proton_inconclusive")


# ---------------------------------------------------------------------- Flickr
@handler("flickr")
async def flickr(fetcher, site, email):
    home = await fetcher.get("https://www.flickr.com/")
    keys = set(re.findall(r"[a-f0-9]{32}", home.text or ""))
    for key in list(keys)[:4]:
        resp = await fetcher.request(
            "https://api.flickr.com/services/rest?method=flickr.people.search"
            f"&api_key={key}&username={email}&format=json&nojsoncallback=1&per_page=5",
            method="GET",
        )
        data = _json(resp)
        if isinstance(data, dict) and (data.get("people") or {}).get("person"):
            person = data["people"]["person"][0]
            return _r(FOUND, 0.8, "flickr_people_search",
                      f"https://www.flickr.com/people/{person.get('nsid', '')}/",
                      name=person.get("realname"), username=person.get("username"))
    return _r(UNKNOWN, 0.0, "flickr_no_key_or_no_hit")
