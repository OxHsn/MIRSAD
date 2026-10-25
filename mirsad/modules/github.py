"""GitHub OSINT — profile, orgs, keys, repos and commit identities.

Mechanism from GitFive: the public API already exposes more identity than
people expect — commit author emails, real names, SSH/GPG keys, linked social
accounts and organisation membership.
"""

from __future__ import annotations

import asyncio

from ..config import Settings
from ..core.http import Fetcher
from ..core.models import FOUND, NOT_FOUND, UNKNOWN, Finding

API = "https://api.github.com"


def _headers(settings: Settings) -> dict:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


async def _get(fetcher: Fetcher, path: str, settings: Settings):
    resp = await fetcher.get(f"{API}{path}", headers=_headers(settings))
    if not resp.ok:
        return None
    import json
    try:
        return json.loads(resp.text)
    except Exception:
        return None


async def investigate(
    fetcher: Fetcher, username: str, settings: Settings, max_repos: int = 3
) -> list[Finding]:
    username = username.strip().lstrip("@")
    user = await _get(fetcher, f"/users/{username}", settings)
    if not isinstance(user, dict) or user.get("message"):
        return [Finding(
            module="github", kind="account", platform="GitHub", identifier=username,
            status=NOT_FOUND if isinstance(user, dict) else UNKNOWN,
            url=f"https://github.com/{username}", source="gitfive",
            data={"reason": "not_found" if isinstance(user, dict) else "api_error"},
        )]

    login = user.get("login") or username
    profile = {
        "username": login,
        "name": user.get("name"),
        "bio": user.get("bio"),
        "company": user.get("company"),
        "location": user.get("location"),
        "blog": user.get("blog"),
        "twitter": user.get("twitter_username"),
        "public_email": user.get("email"),
        "followers": user.get("followers"),
        "following": user.get("following"),
        "public_repos": user.get("public_repos"),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
        "avatar": user.get("avatar_url"),
        "hireable": user.get("hireable"),
    }

    findings: list[Finding] = [
        Finding(
            module="github", kind="account", platform="GitHub", identifier=username,
            status=FOUND, confidence=1.0, url=f"https://github.com/{login}",
            data={**profile, "domain": "github.com"}, source="gitfive", tags=["coding", "high-value"],
        ),
        Finding(
            module="github", kind="profile", platform="GitHub", identifier=login,
            status=FOUND, confidence=1.0, url=f"https://github.com/{login}",
            data={**{k: v for k, v in profile.items() if v}, "domain": "github.com"}, source="gitfive", tags=["profile"],
        ),
    ]

    orgs, keys, gpg, social = await asyncio.gather(
        _get(fetcher, f"/users/{login}/orgs", settings),
        _get(fetcher, f"/users/{login}/keys", settings),
        _get(fetcher, f"/users/{login}/gpg_keys", settings),
        _get(fetcher, f"/users/{login}/social_accounts", settings),
    )

    if isinstance(orgs, list) and orgs:
        findings.append(Finding(
            module="github", kind="identity", platform="GitHub orgs", identifier=login,
            status=FOUND, confidence=0.95,
            data={"orgs": [{"login": o.get("login"), "url": o.get("url")} for o in orgs]},
            source="gitfive", tags=["organisation"],
        ))
    if isinstance(keys, list) and keys:
        findings.append(Finding(
            module="github", kind="identity", platform="GitHub SSH keys", identifier=login,
            status=FOUND, confidence=0.95,
            data={"ssh_keys": [{"title": k.get("title"), "key": (k.get("key") or "")[:80] + "..."} for k in keys]},
            source="gitfive", tags=["ssh"],
        ))
    if isinstance(gpg, list) and gpg:
        findings.append(Finding(
            module="github", kind="identity", platform="GitHub GPG keys", identifier=login,
            status=FOUND, confidence=0.95,
            data={"gpg_keys": [{"key_id": g.get("key_id"), "emails": g.get("emails")} for g in gpg]},
            source="gitfive", tags=["pgp"],
        ))
    if isinstance(social, list) and social:
        findings.append(Finding(
            module="github", kind="identity", platform="GitHub social links", identifier=login,
            status=FOUND, confidence=0.95,
            data={"social": [{"provider": s.get("provider"), "url": s.get("url")} for s in social]},
            source="gitfive", tags=["social"],
        ))

    repos = await _get(fetcher, f"/users/{login}/repos?per_page=100&sort=pushed", settings)
    if isinstance(repos, list) and repos:
        top = repos[:max_repos]
        findings.append(Finding(
            module="github", kind="identity", platform="GitHub repos", identifier=login,
            status=FOUND, confidence=0.9,
            data={"repos": [{"name": r.get("name"), "url": r.get("html_url"),
                             "language": r.get("language"), "stars": r.get("stargazers_count"),
                             "fork": r.get("fork")} for r in repos[:20]],
                  "repo_count": len(repos)},
            source="gitfive", tags=["repos"],
        ))

        commit_results = await asyncio.gather(*[
            _get(fetcher, f"/repos/{login}/{r.get('name')}/commits?per_page=50&author={login}", settings)
            for r in top if r.get("name")
        ])
        emails: set[str] = set()
        names: set[str] = set()
        for commits in commit_results:
            if not isinstance(commits, list):
                continue
            for commit in commits:
                payload = commit.get("commit") or {}
                for side in ("author", "committer"):
                    person = payload.get(side) or {}
                    if person.get("email"):
                        emails.add(person["email"].lower())
                    if person.get("name"):
                        names.add(person["name"])
        if emails or names:
            findings.append(Finding(
                module="github", kind="identity", platform="GitHub commits", identifier=login,
                status=FOUND, confidence=0.9,
                data={
                    "emails": sorted(emails),
                    "names": sorted(names),
                    "noreply": sorted(e for e in emails if "noreply" in e),
                },
                source="gitfive", tags=["commit-identity", "email"],
            ))
    return findings
