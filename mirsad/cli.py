"""MIRSAD command line interface."""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

from . import __author__, __version__
from .config import Settings
from .core import sites as site_db
from .core.orchestrator import Orchestrator, detect_type
from .core.ui import RICH, ProgressUI, banner, render_summary
from .report import export
from .report.html import render as render_html

COMMANDS = {"scan", "sites", "cache"}
TYPE_ALIASES = {"username", "email", "domain", "github"}


def add_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", help="username, email or domain")
    parser.add_argument("--type", choices=["auto", "username", "email", "domain", "github"], default="auto")
    parser.add_argument("--tier", type=int, choices=[1, 2, 3], default=3,
                        help="1=core sites only, 2=strong definitions, 3=everything (default)")
    parser.add_argument("--category", action="append", default=[], help="only these categories (repeatable)")
    parser.add_argument("--exclude", action="append", default=[], help="skip these platforms (repeatable)")
    parser.add_argument("--nsfw", action="store_true", help="include NSFW platforms")
    parser.add_argument("--deep", action="store_true", help="extra passes (CT logs, site harvesting)")
    parser.add_argument("--depth", type=int, default=1, help="branching depth (default 1)")
    parser.add_argument("--expand", action="store_true", help="also scan username candidates from an email")

    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--concurrency", type=int, default=40)
    parser.add_argument("--proxy", default=None, help="http://host:port")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--no-verify", dest="strict_email", action="store_false",
                        help="skip the control-address check (faster, more false positives)")

    parser.add_argument("--github-token", default=None)
    parser.add_argument("--hibp-key", default=None)
    parser.add_argument("--breach-dir", default=None, help="folder of local breach dumps")

    parser.add_argument("--json", dest="json_path", default=None, help="write JSON here")
    parser.add_argument("--csv", dest="csv_path", default=None, help="write CSV here")
    parser.add_argument("--md", dest="md_path", default=None, help="write Markdown here")
    parser.add_argument("--html", dest="html_path", default=None, help="write HTML report here")
    parser.add_argument("--out", default="reports", help="report folder (default: reports)")
    parser.add_argument("--no-report", action="store_true", help="do not auto-write JSON/HTML")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mirsad",
        description="MIRSAD — unified identity intelligence (username / email / domain / GitHub).",
        epilog="examples:\n"
               "  mirsad johndoe\n"
               "  mirsad john@example.com --depth 2 --html\n"
               "  mirsad scan github torvalds --json out.json\n"
               "  mirsad sites --stats\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version",
                        version=f"mirsad {__version__} · by {__author__}")

    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="investigate a username, email, domain or GitHub account")
    add_scan_args(scan)

    sites_cmd = sub.add_parser("sites", help="inspect the merged platform database")
    sites_cmd.add_argument("--stats", action="store_true")
    sites_cmd.add_argument("--search", default=None)
    sites_cmd.add_argument("--categories", action="store_true")

    cache_cmd = sub.add_parser("cache", help="inspect or clear the response cache")
    cache_cmd.add_argument("--clear", action="store_true")
    cache_cmd.add_argument("--stats", action="store_true")
    return parser


def normalize_argv(argv: list[str]) -> list[str]:
    """`mirsad torvalds` -> `mirsad scan torvalds` (subcommand is optional)."""
    for index, token in enumerate(argv):
        if token.startswith("-"):
            continue
        # only the *first* bare token can be a shortcut: "--type email" must
        # not be mistaken for the "email" shortcut.
        if index == 0 and token in TYPE_ALIASES:
            return ["scan", "--type", token] + argv[1:]
        return argv if token in COMMANDS else ["scan"] + argv
    return argv


def settings_from(args: argparse.Namespace) -> Settings:
    return Settings(
        timeout=args.timeout,
        concurrency=args.concurrency,
        proxy=args.proxy,
        tier=args.tier,
        categories=args.category,
        exclude=args.exclude,
        include_nsfw=args.nsfw,
        use_cache=not args.no_cache,
        depth=args.depth,
        expand=args.expand,
        strict_email=args.strict_email,
        verbose=args.verbose,
        github_token=args.github_token,
        hibp_key=args.hibp_key,
        local_breach_dir=args.breach_dir,
    )


def _slug(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in value)[:60]


def cmd_sites(args: argparse.Namespace) -> int:
    if args.search:
        matches = site_db.find(args.search)
        for site in matches[:60]:
            print(f"{site['kind']:8} {site['name'][:28]:28} {site['domain'][:34]:34} tier{site['tier']} "
                  f"{site.get('category', '')}")
        print(f"\n{len(matches)} match(es)")
        return 0
    if args.categories:
        for cat, count in site_db.categories().items():
            print(f"{cat:16} {count}")
        return 0
    stats = site_db.stats()
    print(f"username sites : {stats['username_sites']}")
    print(f"email services : {stats['email_sites']}")
    print(f"total          : {stats['total']}")
    print(f"tiers          : {stats['tiers']}")
    print(f"sources        : {stats['sources']}")
    return 0


def cmd_cache(args: argparse.Namespace) -> int:
    from .core.cache import Cache
    cache = Cache()
    if args.clear:
        print(f"cleared {cache.clear()} entries")
        return 0
    print(cache.stats())
    return 0


async def run_scan(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    target = args.target.strip()
    kind = args.type if args.type != "auto" else detect_type(target)

    if not args.quiet and RICH and sys.stdout.isatty():
        from rich.console import Console
        Console().print(banner(__version__), end="")

    started = time.time()
    with ProgressUI(enabled=not args.quiet, quiet=args.quiet) as ui:
        if not args.quiet:
            ui.log(f"[bold]target[/] [cyan]{target}[/] · type [cyan]{kind}[/] · "
                   f"tier {settings.tier} · depth {settings.depth}")
        orchestrator = Orchestrator(settings, ui=ui)
        report = await orchestrator.run(target, kind=kind, deep=args.deep)

    if not args.quiet:
        render_summary(report)

    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out)
    written: list[Path] = []
    if args.json_path:
        written.append(export.to_json(report, args.json_path))
    if args.csv_path:
        written.append(export.to_csv(report, args.csv_path))
    if args.md_path:
        written.append(export.to_markdown(report, args.md_path))
    if args.html_path:
        path = Path(args.html_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_html(report), encoding="utf-8")
        written.append(path)

    if not args.no_report and not written:
        out_dir.mkdir(parents=True, exist_ok=True)
        base = out_dir / f"{_slug(target)}-{stamp}"
        json_path = export.to_json(report, base.with_suffix(".json"))
        html_path = base.with_suffix(".html")
        html_path.write_text(render_html(report), encoding="utf-8")
        written = [html_path, json_path]

    if written and not args.quiet:
        print()
        for path in written:
            print(f"  saved  {path}")

    print(f"\n  done in {time.time() - started:.1f}s")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(normalize_argv(raw))

    if args.command == "sites":
        return cmd_sites(args)
    if args.command == "cache":
        return cmd_cache(args)
    if args.command != "scan":
        parser.print_help()
        return 2

    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    try:
        return asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
