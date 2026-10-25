"""Shared probe machinery: request building, handler registry, worker pool."""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any

from ..core import precheck
from ..core.detect import classify, extract_profile, title_name
from ..core.http import Fetcher, fill
from ..core.models import ERROR, FOUND, UNKNOWN, Finding

HANDLERS: dict[str, Callable[..., Awaitable[dict]]] = {}


def handler(name: str):
    def wrap(fn):
        HANDLERS[name] = fn
        return fn
    return wrap


def _sub(value: Any, needle: str) -> Any:
    """Substitute the target value into payloads/headers/templates."""
    if isinstance(value, dict):
        return {k: _sub(v, needle) for k, v in value.items()}
    if isinstance(value, list):
        return [_sub(v, needle) for v in value]
    if isinstance(value, str):
        for token in ("{}", "{username}", "{account}", "{email}"):
            value = value.replace(token, needle)
        return value
    return value


def valid_for(site: dict, value: str) -> bool:
    pattern = site.get("regex")
    if not pattern:
        return True
    try:
        return re.search(pattern, value) is not None
    except re.error:
        return True


async def probe_site(fetcher: Fetcher, site: dict, value: str, module: str) -> Finding:
    """Probe one site definition for one value and return a normalised Finding."""
    name = site.get("name") or site.get("id") or "unknown"
    base = Finding(
        module=module,
        kind="account",
        platform=name,
        identifier=value,
        url=site.get("url", "").replace("{}", value) if "{}" in site.get("url", "") else site.get("url", ""),
        source=",".join(site.get("sources") or []),
        tags=[site.get("category", "misc")] + ([ "nsfw"] if site.get("nsfw") else []),
        data={"category": site.get("category", "misc"), "tier": site.get("tier", 3),
              "domain": site.get("domain", "")},
    )

    if not valid_for(site, value):
        base.status = UNKNOWN
        base.data["reason"] = "value_fails_site_regex"
        return base

    handler_name = site.get("handler")
    if handler_name and handler_name in HANDLERS:
        started = time.perf_counter()
        try:
            result = await HANDLERS[handler_name](fetcher, site, value)
        except Exception as exc:  # handlers must never break the scan
            result = {"status": ERROR, "confidence": 0.0, "reason": type(exc).__name__}
        base.elapsed = time.perf_counter() - started
        base.status = result.get("status", UNKNOWN)
        base.confidence = float(result.get("confidence", 0.0))
        if result.get("url"):
            base.url = result["url"]
        base.data.update(result.get("data") or {})
        base.data["reason"] = result.get("reason", "")
        return base

    ctx = {"cookies": {}, "csrf_token": None, "tokens": {}}
    if site.get("pre_check"):
        try:
            ctx = await precheck.run_pre_check(fetcher, site)
        except Exception:
            pass

    url = fill(precheck.apply(site.get("probe") or site.get("url") or "", ctx), value)
    payload = _sub(precheck.apply(site.get("payload"), ctx), value) if site.get("payload") else None
    headers = _sub(precheck.apply(site.get("headers") or {}, ctx), value)
    if ctx.get("cookies"):
        cookie = precheck.cookie_header(ctx["cookies"])
        if cookie and "cookie" not in {k.lower() for k in headers}:
            headers["Cookie"] = cookie

    if not url or "{}" in url or re.search(r"\{[a-z_]{2,}\}", url):
        base.status = UNKNOWN
        base.data["reason"] = "invalid_template"
        return base

    resp = await fetcher.request(
        url,
        method=site.get("method", "GET"),
        headers=headers or None,
        payload=payload,
        follow_redirects=site.get("follow_redirects", True),
    )

    if not resp.ok:
        base.status = ERROR
        base.data["reason"] = resp.error or "request_failed"
        return base

    verdict = classify(site, resp.status, resp.text, resp.url, needle=value, platform=name)
    base.status = verdict.status
    base.confidence = verdict.confidence
    base.data["reason"] = verdict.reason
    base.data["http_status"] = resp.status
    base.elapsed = resp.elapsed
    if resp.url and resp.url != url:
        base.data["final_url"] = resp.url

    if verdict.status == FOUND:
        profile = extract_profile(resp.text)
        if profile:
            base.data.update(profile)
            if profile.get("title"):
                guess = title_name(profile["title"])
                if guess:
                    base.data.setdefault("name", guess)
        if resp.cached:
            base.data["cached"] = True
    return base


async def run_sites(
    fetcher: Fetcher,
    sites: list[dict],
    value: str,
    module: str,
    on_progress: Callable[[int, int, Finding], None] | None = None,
    workers: int | None = None,
) -> list[Finding]:
    """Probe many sites concurrently with a bounded worker pool."""
    if not sites:
        return []
    queue: asyncio.Queue = asyncio.Queue()
    for site in sites:
        queue.put_nowait(site)
    results: list[Finding] = []
    done = 0
    total = len(sites)
    lock = asyncio.Lock()
    pool = workers or max(4, fetcher.settings.concurrency * 2)

    async def worker() -> None:
        nonlocal done
        while True:
            try:
                site = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                finding = await probe_site(fetcher, site, value, module)
            except Exception as exc:
                finding = Finding(
                    module=module, kind="account", platform=site.get("name", "?"),
                    identifier=value, status=ERROR, data={"reason": type(exc).__name__},
                )
            async with lock:
                results.append(finding)
                done += 1
                if on_progress:
                    try:
                        on_progress(done, total, finding)
                    except Exception:
                        pass

    await asyncio.gather(*[worker() for _ in range(min(pool, total))])
    return results
