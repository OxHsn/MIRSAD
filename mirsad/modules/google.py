"""Google identity oracle (GHunt's gxlu trick) — no login required."""

from __future__ import annotations

from ..core.http import Fetcher
from ..core.models import FOUND, NOT_FOUND, UNKNOWN, Finding


async def check(fetcher: Fetcher, email: str) -> Finding:
    """A Set-Cookie on /mail/gxlu means the address is a Google account."""
    resp = await fetcher.request(
        "https://mail.google.com/mail/gxlu",
        method="GET",
        headers={"User-Agent": "Mozilla/5.0"},
        cache=False,
    )
    finding = Finding(
        module="google", kind="account", platform="Google",
        identifier=email, url="https://accounts.google.com/",
        source="ghunt", tags=["google", "identity"],
    )
    if not resp.ok:
        finding.status = UNKNOWN
        finding.data["reason"] = resp.error or "request_failed"
        return finding

    cookie = any(k.lower() == "set-cookie" for k in resp.headers)
    if cookie:
        finding.status = FOUND
        finding.confidence = 0.9
        finding.data["reason"] = "gxlu_set_cookie"
        finding.data["note"] = "Google account exists (not necessarily Gmail)"
    else:
        finding.status = NOT_FOUND
        finding.confidence = 0.75
        finding.data["reason"] = "gxlu_no_cookie"
    return finding
