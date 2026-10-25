"""Terminal progress + result rendering."""

from __future__ import annotations

import sys
from typing import Any

try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    RICH = True
except Exception:  # pragma: no cover - rich is optional
    RICH = False


class ProgressUI:
    """Live progress for every module running in parallel."""

    def __init__(self, enabled: bool = True, quiet: bool = False) -> None:
        self.enabled = enabled and RICH and sys.stdout.isatty()
        self.quiet = quiet
        self.console = Console() if RICH else None
        self.progress: Progress | None = None
        self.live: Live | None = None
        self.tasks: dict[str, Any] = {}
        self.found_total = 0
        self.header = ""

    def __enter__(self) -> ProgressUI:
        if self.enabled:
            self.progress = Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[bold]{task.description}"),
                BarColumn(bar_width=28, complete_style="cyan", finished_style="green"),
                TextColumn("[green]{task.fields[found]} found"),
                TextColumn("[dim]{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=self.console,
                transient=False,
            )
            self.live = Live(self.progress, console=self.console, refresh_per_second=8)
            self.live.start()
        return self

    def __exit__(self, *exc) -> None:
        if self.live:
            self.live.stop()

    def set_header(self, text: str) -> None:
        self.header = text

    def add(self, module: str, total: int) -> None:
        if not self.progress or module in self.tasks:
            return
        self.tasks[module] = self.progress.add_task(module, total=max(1, total), found=0)

    def tick(self, module: str, platform: str = "", found: bool = False) -> None:
        if not self.progress or module not in self.tasks:
            return
        task = self.tasks[module]
        if found:
            self.found_total += 1
            self.progress.update(task, found=self.progress.tasks[task].fields.get("found", 0) + 1)
        self.progress.advance(task)

    def log(self, message: str) -> None:
        if self.quiet:
            return
        if RICH and self.console:
            self.console.print(message)
        else:
            print(_strip(message))


def _strip(text: str) -> str:
    import re
    return re.sub(r"\[/?[a-zA-Z0-9 #_]+\]", "", text)


def banner(version: str) -> str:
    return (
        "\n[bold cyan]  ███╗   ███╗██╗██████╗ ███████╗ █████╗ ██████╗[/]\n"
        "[bold cyan]  ████╗ ████║██║██╔══██╗██╔════╝██╔══██╗██╔══██╗[/]\n"
        "[bold cyan]  ██╔████╔██║██║██████╔╝███████╗███████║██║  ██║[/]\n"
        "[bold cyan]  ██║╚██╔╝██║██║██╔══██╗╚════██║██╔══██║██║  ██║[/]\n"
        "[bold cyan]  ██║ ╚═╝ ██║██║██║  ██║███████║██║  ██║██████╔╝[/]\n"
        "[bold cyan]  ╚═╝     ╚═╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ [/]\n"
        f"[dim]  unified identity intelligence · v{version} · by 0xHsn[/]\n"
    )


def render_summary(report, console: Console | None = None) -> None:
    if not RICH:
        _plain_summary(report)
        return
    console = console or Console()
    score = report.score or {}
    summary = report.summary()

    color = {"critical": "bold red", "elevated": "bold yellow", "moderate": "yellow", "low": "green"}.get(
        score.get("band", "low"), "white"
    )
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column(style="bold")
    grid.add_row("target", report.target)
    grid.add_row("type", report.target_type)
    grid.add_row("exposure", f"[{color}]{score.get('score', 0)}/100 · {score.get('band', 'low')}[/]")
    grid.add_row("accounts", str(summary["accounts"]))
    grid.add_row("breaches", str(summary["breaches"]))
    grid.add_row("duration", f"{report.finished - report.started:.1f}s")
    console.print(Panel(grid, title="[bold cyan]MIRSAD report", border_style="cyan"))

    found = [f for f in report.findings if f.status == "found"]
    if not found:
        console.print("[dim]no public accounts confirmed[/]")
        return
    table = Table(show_header=True, header_style="bold cyan", box=None, pad_edge=False)
    table.add_column("platform", style="bold")
    table.add_column("kind", style="dim")
    table.add_column("confidence", justify="right")
    table.add_column("detail", style="dim", overflow="fold")
    for f in sorted(found, key=lambda x: (x.kind, -x.confidence))[:60]:
        detail = f.url or f.data.get("note") or f.data.get("reason", "")
        if f.kind == "breach":
            detail = ", ".join(b["name"] for b in (f.data.get("breaches") or [])[:4]) or detail
        table.add_row(f.platform, f.kind, f"{f.confidence:.2f}", str(detail)[:110])
    console.print(table)

    drivers = score.get("drivers") or []
    if drivers:
        console.print("\n[bold]why this score[/]")
        for d in drivers[:8]:
            console.print(f"  [cyan]+{d['points']:>4}[/] {d['label']} — [dim]{d['detail']}[/]")


def _plain_summary(report) -> None:
    summary = report.summary()
    score = report.score or {}
    print(f"\ntarget   : {report.target} ({report.target_type})")
    print(f"exposure : {score.get('score', 0)}/100 ({score.get('band', 'low')})")
    print(f"accounts : {summary['accounts']}  breaches: {summary['breaches']}")
    for f in report.found()[:60]:
        print(f"  [{f.kind}] {f.platform} {f.url}")
