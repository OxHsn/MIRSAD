"""JSON / CSV / Markdown exports."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..core.models import Report


def to_json(report: Report, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def to_csv(report: Report, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["kind", "module", "platform", "identifier", "status", "confidence", "url", "source", "detail", "data"]
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for f in report.findings:
            detail = f.data.get("reason") or f.data.get("note") or ""
            if f.kind == "breach":
                names = [b.get("name") for b in (f.data.get("breaches") or []) if b.get("name")]
                detail = ", ".join(names[:10]) or detail
            writer.writerow({
                "kind": f.kind, "module": f.module, "platform": f.platform,
                "identifier": f.identifier, "status": f.status,
                "confidence": f"{f.confidence:.2f}", "url": f.url,
                "source": f.source, "detail": detail,
                "data": json.dumps(f.data, ensure_ascii=False)[:2000],
            })
    return path


def to_markdown(report: Report, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    score = report.score or {}
    lines = [
        f"# MIRSAD report — {report.target}",
        "",
        f"- **type**: {report.target_type}",
        f"- **exposure**: {score.get('score', 0)}/100 ({score.get('band', 'low')})",
        f"- **accounts**: {score.get('accounts_found', 0)}",
        f"- **breaches**: {score.get('breaches', 0)}",
        "",
        "## Findings",
        "",
        "| kind | platform | confidence | detail |",
        "| --- | --- | --- | --- |",
    ]
    for f in report.found():
        detail = (f.url or f.data.get("reason") or f.data.get("note") or "").replace("|", "\\|")
        lines.append(f"| {f.kind} | {f.platform} | {f.confidence:.2f} | {detail} |")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
