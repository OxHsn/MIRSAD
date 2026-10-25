"""Async HTTP engine: concurrency, per-host politeness, retries, proxies, cache."""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from urllib.parse import quote, urlparse

import httpx

from ..config import USER_AGENTS, Settings
from .cache import Cache

RETRYABLE = (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)


@dataclass
class Response:
    status: int = 0
    text: str = ""
    url: str = ""
    elapsed: float = 0.0
    error: str | None = None
    cached: bool = False
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None and self.status > 0


class HostLimiter:
    """Token bucket per host — one bad site can't get us banned everywhere."""

    def __init__(self, rate: float = 6.0, burst: float = 6.0) -> None:
        self.rate = rate
        self.burst = burst
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        async with self._lock:
            now = time.monotonic()
            tokens, last = self._state.get(host, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                wait = (1 - tokens) / self.rate
            else:
                wait = 0.0
            tokens -= 1
            self._state[host] = (tokens, now + wait)
        if wait:
            await asyncio.sleep(wait)


class Fetcher:
    """One client, shared by every module."""

    def __init__(self, settings: Settings, cache: Cache | None = None) -> None:
        self.settings = settings
        self.cache = cache
        self.sem = asyncio.Semaphore(max(1, settings.concurrency))
        self.limiter = HostLimiter(rate=8.0, burst=8.0)
        self._client: httpx.AsyncClient | None = None
        self.requests = 0
        self.cached_hits = 0
        self.errors = 0
        self._ua_index = 0

    async def __aenter__(self) -> Fetcher:
        limits = httpx.Limits(max_connections=self.settings.concurrency * 2,
                              max_keepalive_connections=self.settings.concurrency)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.timeout),
            limits=limits,
            follow_redirects=True,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
            proxy=self.settings.proxy,
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client:
            await self._client.aclose()

    def _ua(self) -> str:
        if self.settings.user_agent:
            return self.settings.user_agent
        self._ua_index = (self._ua_index + 1) % len(USER_AGENTS)
        return USER_AGENTS[self._ua_index]

    async def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict | None = None,
        payload=None,
        form: dict | None = None,
        follow_redirects: bool = True,
        cache: bool = True,
    ) -> Response:
        assert self._client is not None, "Fetcher must be used as an async context manager"
        if not url:
            return Response(error="empty_url")

        key = Cache.make_key(method, url, payload or form) if cache and self.cache else None
        if key and self.cache:
            hit = self.cache.get(key)
            if hit:
                status, final_url, body = hit
                self.cached_hits += 1
                if status == 0:  # cached failure (timeout / dead host)
                    return Response(error="cached_failure", url=final_url, cached=True)
                return Response(status=status, text=body, url=final_url, cached=True)

        host = urlparse(url).netloc
        req_headers = {"User-Agent": self._ua()}
        if headers:
            req_headers.update({str(k): str(v) for k, v in headers.items()})

        last_error: str | None = None
        for attempt in range(self.settings.retries + 1):
            try:
                async with self.sem:
                    await self.limiter.acquire(host)
                    started = time.perf_counter()
                    self.requests += 1
                    resp = await self._client.request(
                        method.upper(),
                        url,
                        headers=req_headers,
                        json=payload if isinstance(payload, (dict, list)) else None,
                        data=form if form is not None else (payload if isinstance(payload, str) else None),
                        follow_redirects=follow_redirects,
                    )
                    elapsed = time.perf_counter() - started
                text = resp.text
                if key and self.cache and resp.status_code < 500:
                    self.cache.set(key, resp.status_code, str(resp.url), text)
                return Response(
                    status=resp.status_code, text=text, url=str(resp.url), elapsed=elapsed,
                    headers=dict(resp.headers), cookies=dict(resp.cookies),
                )
            except RETRYABLE as exc:
                last_error = type(exc).__name__
                self.errors += 1
                # A read timeout means the host is dead or throttling us —
                # retrying just burns the scan budget. Cache the failure so a
                # repeat run doesn't pay for it again.
                if isinstance(exc, httpx.TimeoutException):
                    if key and self.cache:
                        self.cache.set(key, 0, url, "", ttl=3600)
                    return Response(error="timeout", url=url)
                if attempt < self.settings.retries:
                    await asyncio.sleep(0.3 * (2 ** attempt) + random.random() * 0.2)
                    continue
                if key and self.cache:
                    self.cache.set(key, 0, url, "", ttl=1800)
                return Response(error=last_error, url=url)
            except httpx.HTTPError as exc:
                self.errors += 1
                return Response(error=type(exc).__name__, url=url)
            except Exception as exc:  # never let one site kill a scan
                self.errors += 1
                return Response(error=f"{type(exc).__name__}", url=url)
        return Response(error=last_error or "unknown", url=url)

    # ------------------------------------------------------------------ helpers
    async def get(self, url: str, **kw) -> Response:
        return await self.request(url, method="GET", **kw)

    async def post(self, url: str, payload=None, **kw) -> Response:
        return await self.request(url, method="POST", payload=payload, **kw)

    async def json(self, url: str, **kw):
        resp = await self.get(url, **kw)
        if not resp.ok:
            return None
        try:
            import json as _json
            return _json.loads(resp.text)
        except Exception:
            return None

    def stats(self) -> dict:
        return {
            "requests": self.requests,
            "cached": self.cached_hits,
            "errors": self.errors,
        }


def fill(template: str, value: str) -> str:
    """Substitute the placeholder in a site template, URL-encoding the value."""
    if "{}" not in template:
        return template
    return template.replace("{}", quote(str(value), safe=""))
