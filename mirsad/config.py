"""Runtime configuration: paths, tunables, API keys."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
DATA_DIR = PKG_DIR / "data"
# Cache lives next to the working directory by default: predictable, writable,
# and easy to wipe. Override with MIRSAD_HOME.
CACHE_DIR = Path(os.environ.get("MIRSAD_HOME", Path.cwd() / ".mirsad"))
CACHE_DB = CACHE_DIR / "cache.db"

DEFAULT_TIMEOUT = 10.0
DEFAULT_CONCURRENCY = 40
DEFAULT_RETRIES = 2
CACHE_TTL = 60 * 60 * 24  # 24h

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

# High-signal services used by the exposure score.
HIGH_VALUE = {
    "github", "gitlab", "google", "microsoft", "apple", "amazon", "paypal",
    "binance", "coinbase", "kraken", "stripe", "revolut", "wise", "bank",
    "instagram", "facebook", "twitter", "x", "linkedin", "tiktok", "telegram",
    "whatsapp", "discord", "steam", "spotify", "netflix", "uber", "airbnb",
    "dropbox", "icloud", "protonmail", "yahoo", "outlook", "adobe", "canva",
    "notion", "slack", "zoom", "shopify", "ebay", "aliexpress", "booking",
}

BANK_WORDS = ("bank", "banco", "banque", "bk", "pay", "wallet", "crypto", "exchange")


@dataclass
class Settings:
    """Everything a scan needs, resolved from CLI flags + environment."""

    timeout: float = DEFAULT_TIMEOUT
    concurrency: int = DEFAULT_CONCURRENCY
    retries: int = DEFAULT_RETRIES
    proxy: str | None = None
    tier: int = 3
    categories: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    include_nsfw: bool = False
    only_found: bool = True
    use_cache: bool = True
    cache_ttl: int = CACHE_TTL
    depth: int = 1
    max_branch: int = 25
    expand: bool = False
    strict_email: bool = True  # verify every hit against a control address
    user_agent: str | None = None
    verbose: bool = False
    # credentials
    github_token: str | None = None
    hibp_key: str | None = None
    hunter_key: str | None = None
    intelx_key: str | None = None
    local_breach_dir: str | None = None

    def __post_init__(self) -> None:
        self.github_token = self.github_token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.hibp_key = self.hibp_key or os.environ.get("HIBP_API_KEY")
        self.hunter_key = self.hunter_key or os.environ.get("HUNTER_API_KEY")
        self.intelx_key = self.intelx_key or os.environ.get("INTELX_API_KEY")
        self.local_breach_dir = self.local_breach_dir or os.environ.get("MIRSAD_BREACH_DIR")
        self.proxy = self.proxy or os.environ.get("MIRSAD_PROXY")
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
