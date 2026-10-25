"""Unified data model shared by every module and report."""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

ALIASES = {
    "threads.net": "threads.com", "twitter.com": "x.com", "pscp.tv": "periscope.tv",
    "t.co": "x.com", "old.reddit.com": "reddit.com", "np.reddit.com": "reddit.com",
    "m.youtube.com": "youtube.com", "youtu.be": "youtube.com",
    "githubusercontent.com": "github.com", "api.github.com": "github.com",
}


def base_domain(domain: str) -> str:
    """api.dailymotion.com -> dailymotion.com (good enough for de-duplication)."""
    parts = [p for p in str(domain).lower().split(".") if p]
    base = ".".join(parts[-2:]) if len(parts) >= 2 else ".".join(parts)
    return ALIASES.get(base, base)


FOUND = "found"
NOT_FOUND = "not_found"
UNKNOWN = "unknown"
BLOCKED = "blocked"
ERROR = "error"
INFO = "info"


@dataclass
class Finding:
    """One fact discovered about the target.

    ``kind`` groups facts for the report:
    account | profile | breach | dns | paste | identity | leak | note
    """

    module: str
    kind: str
    platform: str
    identifier: str
    status: str = INFO
    url: str = ""
    confidence: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    tags: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    def key(self) -> tuple:
        domain = self.data.get("domain")
        platform = base_domain(domain) if domain else self.platform.lower()
        return (self.kind, platform, self.identifier.lower())

    def to_dict(self) -> dict:
        return asdict(self)


class EntityGraph:
    """Nodes + edges — the identity graph every source feeds into."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple[str, str, str], dict] = {}

    @staticmethod
    def _nid(kind: str, value: str) -> str:
        return f"{kind}:{value.strip().lower()}"

    def add_node(self, kind: str, value: str, label: str | None = None, **attrs: Any) -> str:
        nid = self._nid(kind, value)
        node = self.nodes.get(nid)
        if node is None:
            node = {"id": nid, "type": kind, "value": value, "label": label or value, "attrs": {}}
            self.nodes[nid] = node
        node["attrs"].update({k: v for k, v in attrs.items() if v not in (None, "", [])})
        return nid

    def add_edge(self, src: str, dst: str, relation: str, **attrs: Any) -> None:
        key = (src, dst, relation)
        if key not in self.edges:
            self.edges[key] = {"source": src, "target": dst, "relation": relation, "attrs": attrs}

    def link(self, kind_a: str, value_a: str, kind_b: str, value_b: str, relation: str, **attrs: Any) -> None:
        a = self.add_node(kind_a, value_a)
        b = self.add_node(kind_b, value_b)
        self.add_edge(a, b, relation, **attrs)

    def to_dict(self) -> dict:
        return {"nodes": list(self.nodes.values()), "edges": list(self.edges.values())}

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for node in self.nodes.values():
            out[node["type"]] = out.get(node["type"], 0) + 1
        return out


@dataclass
class Report:
    target: str
    target_type: str
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    graph: EntityGraph = field(default_factory=EntityGraph)
    score: dict[str, Any] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    # ---------------------------------------------------------------- findings
    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        self._ingest(finding)

    def extend(self, findings: Iterable[Finding]) -> None:
        for f in findings:
            self.add(f)

    def _ingest(self, f: Finding) -> None:
        """Feed a finding into the identity graph."""
        g = self.graph
        root = g.add_node(self.target_type, self.target)
        if f.kind == "account" and f.status == FOUND:
            acct = g.add_node("account", f"{f.platform}:{f.identifier}", label=f.platform, url=f.url)
            g.add_edge(root, acct, "has_account")
            for email in f.data.get("emails", []) or []:
                g.link("account", f"{f.platform}:{f.identifier}", "email", email, "exposes_email")
            for name in f.data.get("names", []) or []:
                g.link("account", f"{f.platform}:{f.identifier}", "name", name, "exposes_name")
            for phone in f.data.get("phones", []) or []:
                g.link("account", f"{f.platform}:{f.identifier}", "phone", phone, "exposes_phone")
        elif f.kind == "breach" and f.status == FOUND:
            b = g.add_node("breach", f.platform, label=f.platform)
            g.add_edge(root, b, "breached_in")
        elif f.kind == "profile" and f.status == FOUND:
            g.add_node("profile", f.url or f.identifier, label=f.platform, **f.data)
            g.add_edge(root, g._nid("profile", f.url or f.identifier), "has_profile")
        elif f.kind == "dns" and f.status == FOUND:
            g.add_node("domain", f.identifier, label=f.identifier)
            for host in f.data.get("subdomains", []) or []:
                g.link("domain", f.identifier, "domain", host, "subdomain_of")

    def found(self) -> list[Finding]:
        return [f for f in self.findings if f.status == FOUND]

    def by_kind(self, kind: str) -> list[Finding]:
        return [f for f in self.findings if f.kind == kind]

    def dedupe(self) -> None:
        best: dict[tuple, Finding] = {}
        order: list[tuple] = []
        for f in self.findings:
            k = f.key()
            current = best.get(k)
            if current is None:
                best[k] = f
                order.append(k)
                continue
            if f.confidence > current.confidence:
                # keep whichever carries more profile detail
                if not f.url and current.url:
                    f.url = current.url
                best[k] = f
            elif not current.url and f.url:
                current.url = f.url
        self.findings = [best[k] for k in order]

    # ---------------------------------------------------------------- export
    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "target": self.target,
            "target_type": self.target_type,
            "started": self.started,
            "finished": self.finished or time.time(),
            "duration": round((self.finished or time.time()) - self.started, 2),
            "score": self.score,
            "stats": self.stats,
            "meta": self.meta,
            "findings": [f.to_dict() for f in self.findings],
            "graph": self.graph.to_dict(),
        }

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for f in self.found():
            counts[f.kind] = counts.get(f.kind, 0) + 1
        return {
            "accounts": counts.get("account", 0),
            "breaches": counts.get("breach", 0),
            "profiles": counts.get("profile", 0),
            "total_findings": len(self.findings),
            "found": len(self.found()),
        }
