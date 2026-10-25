"""Clone (or refresh) the upstream projects that feed the site database.

The corpus is generated, not hand-written: `tools/build_data.py` reads the
11 upstream repositories and merges their definitions. This script puts them
in `_research/` (git-ignored) so the build is reproducible.

Usage
-----
    python tools/fetch_sources.py            # shallow clone everything
    python tools/fetch_sources.py --update   # git pull the existing clones
    python tools/fetch_sources.py --clean    # remove _research/
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "_research"

SOURCES = {
    "sherlock": "sherlock-project/sherlock",
    "sylva": "ppfeister/sylva",
    "WhatsMyName": "WebBreacher/WhatsMyName",
    "GitFive": "mxrch/GitFive",
    "GHunt": "mxrch/GHunt",
    "holehe": "megadose/holehe",
    "h8mail": "khast3x/h8mail",
    "blackbird": "antoniaci/blackbird",
    "Eyes": "N0rz3/Eyes",
    "Zehef": "N0rz3/Zehef",
    "MailAccess": "KatrielMoses/MailAccess",
}


def run(cmd: list[str], cwd: Path | None = None) -> bool:
    try:
        subprocess.run(cmd, cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or b"").decode("utf-8", "ignore").strip().splitlines()
        print(f"    failed: {detail[-1] if detail else exc}")
        return False
    except FileNotFoundError:
        print("    git is not installed or not on PATH")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch the upstream OSINT sources")
    parser.add_argument("--update", action="store_true", help="pull existing clones instead of cloning")
    parser.add_argument("--clean", action="store_true", help="delete _research/ and exit")
    args = parser.parse_args()

    if args.clean:
        if DEST.exists():
            shutil.rmtree(DEST)
            print(f"removed {DEST}")
        return 0

    DEST.mkdir(exist_ok=True)
    ok, failed = 0, []

    for name, repo in SOURCES.items():
        target = DEST / name
        if target.exists():
            if args.update:
                print(f"  updating {name}")
                if run(["git", "-C", str(target), "pull", "--ff-only", "-q"]):
                    ok += 1
                else:
                    failed.append(name)
            else:
                print(f"  skip     {name} (already present)")
                ok += 1
            continue

        print(f"  cloning  {name}")
        if run(["git", "clone", "--depth", "1", "-q", f"https://github.com/{repo}.git", str(target)]):
            ok += 1
        else:
            failed.append(name)

    print(f"\n{ok}/{len(SOURCES)} sources ready in {DEST}")
    if failed:
        print("failed:", ", ".join(failed))
        print("You can still build with whatever is present; missing sources are skipped.")
    print("\nnext: python tools/build_data.py")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
