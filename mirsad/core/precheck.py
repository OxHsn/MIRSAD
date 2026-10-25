"""Session bootstrap: cookies / CSRF / named tokens before a probe.

Ported mechanism from MailAccess: many signup forms reject a bare request
unless you first load the page and replay its CSRF token and cookies.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any

_SELECTOR_RE = re.compile(
    r"""^\s*(?P<tag>meta|input)\s*\[\s*name\s*=\s*['"](?P<name>[^'"]+)['"]\s*\]\s*$""",
    re.IGNORECASE,
)


class _SelectorParser(HTMLParser):
    def __init__(self, selector: str) -> None:
        super().__init__()
        match = _SELECTOR_RE.match(selector)
        if match:
            self._tag = match.group("tag").lower()
            self._name = match.group("name").lower()
        else:
            self._tag = "meta" if "meta" in selector.lower() else "input"
            self._name = "csrf-token"
        self._value_attr = "content" if self._tag == "meta" else "value"
        self.value: str | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        if self.value is not None or tag.lower() != self._tag:
            return
        attributes = {k.lower(): v or "" for k, v in attrs}
        if attributes.get("name", "").lower() == self._name:
            self.value = attributes.get(self._value_attr) or None


def extract_selector(body: str, selector: Any) -> str | None:
    if not isinstance(selector, str) or not selector.strip():
        return None
    parser = _SelectorParser(selector)
    try:
        parser.feed(body)
    except Exception:
        return None
    return parser.value


def extract_tokens(body: str, spec: Any) -> dict[str, str]:
    if not isinstance(spec, dict):
        return {}
    out: dict[str, str] = {}
    for name, pattern in spec.items():
        if not isinstance(name, str) or not isinstance(pattern, str):
            continue
        try:
            match = re.search(pattern, body)
        except re.error:
            continue
        if match:
            out[name] = match.group(1) if match.groups() else match.group(0)
    return out


async def run_pre_check(fetcher, defn: dict) -> dict:
    config = defn.get("pre_check")
    if not isinstance(config, dict) or not config.get("url"):
        return {"cookies": {}, "csrf_token": None, "tokens": {}}

    resp = await fetcher.request(
        config["url"],
        method=str(config.get("method") or "GET").upper(),
        headers=config.get("headers") if isinstance(config.get("headers"), dict) else None,
        payload=config.get("body") or config.get("data"),
        follow_redirects=True,
    )
    body = resp.text or ""
    cookies = dict(resp.cookies or {})
    csrf = extract_selector(body, config.get("extract_csrf"))
    cookie_name = config.get("cookie_name")
    if not csrf and isinstance(cookie_name, str):
        csrf = cookies.get(cookie_name)
    if not csrf:
        csrf = cookies.get("csrftoken") or cookies.get("csrf_token")
    return {"cookies": cookies, "csrf_token": csrf, "tokens": extract_tokens(body, config.get("extract_regex"))}


def apply(value: Any, ctx: dict) -> Any:
    if isinstance(value, dict):
        return {k: apply(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [apply(v, ctx) for v in value]
    if not isinstance(value, str):
        return value
    replacements = {
        "{csrftoken_value}": ctx.get("csrf_token") or "",
        "{csrf_token}": ctx.get("csrf_token") or "",
    }
    for name, token in (ctx.get("cookies") or {}).items():
        replacements[f"{{{name}_value}}"] = str(token)
    for name, token in (ctx.get("tokens") or {}).items():
        replacements[f"{{{name}}}"] = str(token)
    for marker, replacement in replacements.items():
        value = value.replace(marker, replacement)
    return value


def cookie_header(cookies: dict) -> str | None:
    if not cookies:
        return None
    return "; ".join(f"{k}={v}" for k, v in cookies.items())
