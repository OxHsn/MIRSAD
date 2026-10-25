"""Hand-curated email probes.

These services are worth having even though their answer isn't a simple
marker in the HTML: the technique lives in ``mirsad/modules/email_handlers.py``.
Ported behaviour from holehe (megadose), Zehef (N0rz3) and Eyes (N0rz3).
"""

from __future__ import annotations

CURATED: list[dict] = [
    {
        "id": "adobe", "name": "Adobe", "domain": "adobe.com", "category": "software",
        "kind": "email", "url": "https://account.adobe.com/", "probe": "https://account.adobe.com/",
        "handler": "adobe", "tier": 1, "sources": ["zehef", "holehe"], "check": {},
    },
    {
        "id": "amazon", "name": "Amazon", "domain": "amazon.com", "category": "shopping",
        "kind": "email", "url": "https://www.amazon.com/", "probe": "https://www.amazon.com/",
        "handler": "amazon", "tier": 1, "sources": ["holehe"], "check": {},
    },
    {
        "id": "bandlab", "name": "BandLab", "domain": "bandlab.com", "category": "music",
        "kind": "email", "url": "https://www.bandlab.com/", "probe": "https://www.bandlab.com/",
        "handler": "bandlab", "tier": 2, "sources": ["zehef"], "check": {},
    },
    {
        "id": "chess", "name": "Chess.com", "domain": "chess.com", "category": "gaming",
        "kind": "email", "url": "https://www.chess.com/", "probe": "https://www.chess.com/",
        "handler": "chess", "tier": 1, "sources": ["zehef"], "check": {},
    },
    {
        "id": "deezer", "name": "Deezer", "domain": "deezer.com", "category": "music",
        "kind": "email", "url": "https://www.deezer.com/", "probe": "https://www.deezer.com/",
        "handler": "deezer", "tier": 1, "sources": ["zehef", "holehe"], "check": {},
    },
    {
        "id": "duolingo", "name": "Duolingo", "domain": "duolingo.com", "category": "education",
        "kind": "email", "url": "https://www.duolingo.com/", "probe": "https://www.duolingo.com/",
        "handler": "duolingo", "tier": 1, "sources": ["zehef", "eyes"], "check": {},
    },
    {
        "id": "github-email", "name": "GitHub", "domain": "github.com", "category": "coding",
        "kind": "email", "url": "https://github.com/", "probe": "https://github.com/",
        "handler": "github_email", "tier": 1, "sources": ["zehef", "eyes", "gitfive"], "check": {},
    },
    {
        "id": "gravatar", "name": "Gravatar", "domain": "gravatar.com", "category": "misc",
        "kind": "email", "url": "https://gravatar.com/", "probe": "https://gravatar.com/",
        "handler": "gravatar", "tier": 1, "sources": ["zehef", "eyes"], "check": {},
    },
    {
        "id": "imgur", "name": "Imgur", "domain": "imgur.com", "category": "media",
        "kind": "email", "url": "https://imgur.com/", "probe": "https://imgur.com/",
        "handler": "imgur", "tier": 1, "sources": ["zehef", "eyes"], "check": {},
    },
    {
        "id": "instagram", "name": "Instagram", "domain": "instagram.com", "category": "social",
        "kind": "email", "url": "https://www.instagram.com/", "probe": "https://www.instagram.com/",
        "handler": "instagram", "tier": 1, "sources": ["zehef", "eyes", "holehe"], "check": {},
    },
    {
        "id": "pinterest", "name": "Pinterest", "domain": "pinterest.com", "category": "social",
        "kind": "email", "url": "https://www.pinterest.com/", "probe": "https://www.pinterest.com/",
        "handler": "pinterest", "tier": 1, "sources": ["zehef"], "check": {},
    },
    {
        "id": "picsart", "name": "Picsart", "domain": "picsart.com", "category": "art",
        "kind": "email", "url": "https://picsart.com/", "probe": "https://picsart.com/",
        "handler": "picsart", "tier": 2, "sources": ["zehef"], "check": {},
    },
    {
        "id": "pornhub", "name": "Pornhub", "domain": "pornhub.com", "category": "nsfw",
        "kind": "email", "url": "https://www.pornhub.com/", "probe": "https://www.pornhub.com/",
        "handler": "pornhub", "tier": 3, "nsfw": True, "sources": ["zehef"], "check": {},
    },
    {
        "id": "strava", "name": "Strava", "domain": "strava.com", "category": "sport",
        "kind": "email", "url": "https://www.strava.com/", "probe": "https://www.strava.com/",
        "handler": "strava", "tier": 1, "sources": ["zehef"], "check": {},
    },
    {
        "id": "twitter", "name": "X (Twitter)", "domain": "x.com", "category": "social",
        "kind": "email", "url": "https://x.com/", "probe": "https://x.com/",
        "handler": "twitter_email", "tier": 1, "sources": ["zehef", "eyes", "holehe"], "check": {},
    },
    {
        "id": "protonmail", "name": "Proton Mail", "domain": "proton.me", "category": "misc",
        "kind": "email", "url": "https://account.proton.me/", "probe": "https://account.proton.me/",
        "handler": "protonmail", "tier": 2, "sources": ["zehef", "eyes"], "check": {},
    },
    {
        "id": "flickr", "name": "Flickr", "domain": "flickr.com", "category": "media",
        "kind": "email", "url": "https://www.flickr.com/", "probe": "https://www.flickr.com/",
        "handler": "flickr", "tier": 2, "sources": ["zehef"], "check": {},
    },
]
