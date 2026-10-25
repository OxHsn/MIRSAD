"""Exposure + credential-risk scoring (MailAccess-style, but transparent)."""

from __future__ import annotations

from ..config import BANK_WORDS, HIGH_VALUE
from .models import FOUND, Report


def _band(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "elevated"
    if score >= 20:
        return "moderate"
    return "low"


def _is_high_value(platform: str) -> bool:
    key = platform.lower().replace(" ", "")
    if key in HIGH_VALUE:
        return True
    return any(word in key for word in BANK_WORDS)


def compute(report: Report) -> dict:
    accounts = [f for f in report.findings if f.kind == "account" and f.status == FOUND]
    breaches = [f for f in report.findings if f.kind == "breach" and f.status == FOUND]
    identities = [f for f in report.findings if f.kind == "identity" and f.status == FOUND]
    dns = [f for f in report.findings if f.kind == "dns"]

    drivers: list[dict] = []

    def add(label: str, points: float, detail: str, severity: str = "info") -> None:
        if points <= 0:
            return
        drivers.append({"label": label, "points": round(points, 1), "detail": detail, "severity": severity})

    # ---------------------------------------------------------------- accounts
    hv = [a for a in accounts if _is_high_value(a.platform)]
    account_points = min(30.0, len(accounts) * 1.2)
    add("Account footprint", account_points,
        f"{len(accounts)} public account(s) across the checked platforms")
    if hv:
        add("High-value accounts", min(15.0, len(hv) * 2.5),
            ", ".join(sorted({a.platform for a in hv})[:8]), "high")

    # ---------------------------------------------------------------- breaches
    if breaches:
        add("Breach exposure", min(25.0, len(breaches) * 4.0),
            f"present in {len(breaches)} known breach source(s)", "high")
        plain = [b for b in breaches if b.data.get("passwords") or b.data.get("cleartext")]
        if plain:
            add("Cleartext credentials", 12.0,
                f"{len(plain)} source(s) expose passwords or hashes", "critical")
        stealer = [b for b in breaches if b.data.get("stealer")]
        if stealer:
            add("Infostealer logs", 10.0,
                "credentials captured by malware on an infected device", "critical")

    # ------------------------------------------------------------------ google
    google = [f for f in report.findings if f.module == "google" and f.status == FOUND]
    if google:
        add("Google account", 4.0, "address is a Google identity (gxlu oracle)")

    # ------------------------------------------------------------ domain health
    for f in dns:
        if f.data.get("spf") is False:
            add("Missing SPF", 4.0, f"{f.identifier} publishes no SPF record", "medium")
        if f.data.get("dmarc") is False:
            add("Missing DMARC", 6.0, f"{f.identifier} publishes no DMARC policy", "medium")
        if f.data.get("disposable"):
            add("Disposable domain", 3.0, f"{f.identifier} is a throwaway mail provider")
        if f.data.get("catch_all"):
            add("Catch-all domain", 2.0, "domain accepts mail for any local part")

    # ---------------------------------------------------------------- identity
    names = {i.data.get("name") for i in identities if i.data.get("name")}
    phones = {i.data.get("phone") for i in identities if i.data.get("phone")}
    if names:
        add("Real name exposed", 4.0, ", ".join(sorted(n for n in names if n))[:120])
    if phones:
        add("Phone exposed", 5.0, ", ".join(sorted(p for p in phones if p))[:120], "high")

    pastes = [f for f in report.findings if f.kind == "paste" and f.status == FOUND]
    if pastes:
        add("Paste mentions", 5.0, f"{len(pastes)} paste(s) reference the target", "high")

    score = int(min(100.0, sum(d["points"] for d in drivers)))

    # ------------------------------------------------------- credential risk
    cred = 0.0
    if breaches:
        cred += min(50.0, len(breaches) * 8.0)
    if any(b.data.get("passwords") for b in breaches):
        cred += 25.0
    if any(b.data.get("stealer") for b in breaches):
        cred += 20.0
    if any(b.data.get("hash") for b in breaches):
        cred += 5.0
    cred = int(min(100.0, cred))

    return {
        "score": score,
        "band": _band(score),
        "drivers": sorted(drivers, key=lambda d: -d["points"]),
        "credential_risk": cred,
        "credential_band": _band(cred),
        "accounts_found": len(accounts),
        "high_value_accounts": len(hv),
        "breaches": len(breaches),
    }
