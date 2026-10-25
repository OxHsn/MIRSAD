"""Use MIRSAD as a library instead of a CLI.

    python examples/library_usage.py torvalds

Everything the CLI does is available programmatically: build a `Settings`, hand it to
the orchestrator, get a `Report` back. The report is a plain dataclass, so you can
filter it, feed it into your own pipeline, or render it.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

try:
    import mirsad  # noqa: F401
except ModuleNotFoundError:  # running from a checkout that isn't pip-installed
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirsad.config import Settings
from mirsad.core.models import FOUND
from mirsad.core.orchestrator import Orchestrator, detect_type
from mirsad.report import export
from mirsad.report.html import render


async def investigate(target: str) -> None:
    settings = Settings(
        tier=1,            # 1 = 128 core platforms, 2 = ~2,500, 3 = everything
        depth=1,           # one level of branching
        concurrency=40,
        timeout=10.0,
    )

    report = await Orchestrator(settings).run(target, kind=detect_type(target))

    print(f"\ntarget   : {report.target} ({report.target_type})")
    print(f"exposure : {report.score['score']}/100 ({report.score['band']})")
    print(f"duration : {report.finished - report.started:.1f}s")

    accounts = [f for f in report.findings if f.kind == "account" and f.status == FOUND]
    print(f"accounts : {len(accounts)}\n")
    for finding in sorted(accounts, key=lambda f: -f.confidence):
        print(f"  {finding.platform:<24} {finding.confidence:.2f}  {finding.url}")

    out = Path("reports")
    out.mkdir(exist_ok=True)
    export.to_json(report, out / "library-example.json")
    (out / "library-example.html").write_text(render(report), encoding="utf-8")
    print(f"\nwritten to {out}/library-example.{{json,html}}")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "torvalds"
    asyncio.run(investigate(target))
