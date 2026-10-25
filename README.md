# MIRSAD · مرصاد

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-22d3ee.svg"></a>
  <a href="https://www.python.org/"><img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776ab.svg"></a>
  <img alt="Tests" src="https://img.shields.io/badge/tests-25%20passing-34d399.svg">
  <img alt="Platforms" src="https://img.shields.io/badge/platforms-4%2C793-0a0e14.svg">
  <a href="https://github.com/OxHsn"><img alt="GitHub" src="https://img.shields.io/badge/github-OxHsn-181717.svg"></a>
  <a href="https://instagram.com/Y.ut"><img alt="Instagram" src="https://img.shields.io/badge/instagram-Y.ut-e1306c.svg"></a>
</p>

<p align="center"><b>Unified identity intelligence — one tool, one schema, one report.</b></p>

MIRSAD merges the *mechanisms* of eleven open-source OSINT projects into a single
async engine: 4,577 username checks, 216 email-existence probes, GitHub commit-identity
analysis, breach lookups, domain forensics and a recursive identity graph — all behind
one command.

```bash
mirsad torvalds                     # auto-detects a username
mirsad john@company.com --depth 2   # email → accounts → domain → breaches
mirsad company.com --deep           # DNS, SPF/DMARC, CT subdomains, harvest
mirsad github torvalds --expand     # GitHub → commit emails → email sweep
```

> **نظرة سريعة:** أداة واحدة تدمج 11 مشروع OSINT. تكتب اسم مستخدم أو بريد أو نطاق،
> فتشغّل كل الفحوصات بالتوازي، تربط النتائج في رسم هوية واحد، وتخرج تقرير HTML + JSON
> مع درجة تعرّض من 100. كل نتيجة تحمل درجة ثقة وسبباً واضحاً.

---

## What was merged, and why

| Project | Mechanism taken | Where it lives now |
| --- | --- | --- |
| **Sherlock** | 480 site definitions, `status_code` / `message` / `response_url` detection, WAF fingerprints, `regexCheck`, `urlProbe` | `core/detect.py`, `data/sites.json` |
| **WhatsMyName** | 670 two-marker definitions (`e_code`/`e_string` vs `m_code`/`m_string`) | `core/detect.py` (`two_marker` mode) |
| **Sylva** | Branching identity discovery: results become new queries; flat unified record schema | `core/orchestrator.py`, `core/models.py` |
| **GitFive** | GitHub OSINT: commit author emails, real names, SSH/GPG keys, orgs, repo analysis | `modules/github.py` |
| **GHunt** | The `gxlu` oracle — any address can be checked for a Google account with no login | `modules/google.py` |
| **holehe** | 147 per-service email probes; the "silent" password-recovery/registration techniques | `modules/email_handlers.py`, `data/sites.json` |
| **h8mail** | Breach API fan-out (HIBP), local dump search (plain + `.gz`), recursive chasing | `modules/breach.py` |
| **Blackbird** | WhatsMyName-driven engine, permutation generator, export ergonomics | `modules/patterns.py`, `report/` |
| **Eyes** | Email → account modules (Duolingo, Gravatar, Imgur, Instagram, X…) | `modules/email_handlers.py` |
| **Zehef** | JSON-logic probes (Adobe, Deezer, Chess, Spotify, Strava, Picsart…), HudsonRock stealer feed | `modules/email_handlers.py`, `modules/breach.py` |
| **MailAccess** | 5,360-definition corpus, unified probe detector, **control-address disambiguation**, CSRF/cookie pre-checks, pattern index | `core/detect.py`, `core/precheck.py`, `data/` |

Nothing is vendored as a dependency. The behaviour was re-implemented against one
schema so a single engine can run every definition without caring where it came from.

---

## Install

```bash
git clone https://github.com/OxHsn/mirsad.git && cd mirsad
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Dependencies: `httpx`, `dnspython`, `rich`. Python 3.10+.

The site database ships pre-built (`mirsad/data/sites.json`), so the tool works
immediately. To rebuild it from the upstream projects:

```bash
python tools/fetch_sources.py     # shallow-clones the 11 projects into _research/
python tools/build_data.py        # merges them into mirsad/data/sites.json
```

`_research/` is git-ignored; it is research material, not part of the package.

---

## Usage

```
mirsad [command] <target> [options]

commands
  scan      investigate a target (default when you just pass a target)
  sites     inspect the merged platform database
  cache     show or clear the response cache

shortcuts
  mirsad username <name>     mirsad email <addr>
  mirsad domain <dom>        mirsad github <login>
```

### Common flags

| Flag | Meaning |
| --- | --- |
| `--tier {1,2,3}` | 1 = 128 core platforms (fast), 2 = ~2,500 strong definitions, 3 = everything |
| `--category` | only these categories (`social`, `coding`, `finance`…) — repeatable |
| `--exclude` | skip platforms — repeatable |
| `--depth N` | how many branching levels (default 1) |
| `--expand` | also branch into derived identifiers (commit emails, local-part usernames) |
| `--deep` | domain extras: certificate transparency, website email harvest |
| `--no-verify` | skip the control-address check on email hits (faster, noisier) |
| `--concurrency` | parallel requests (default 40) |
| `--timeout` | per-request seconds (default 10) |
| `--proxy` | `http://host:port` |
| `--no-cache` | bypass the SQLite response cache |
| `--json/--csv/--md/--html` | write specific artefacts |
| `--out DIR` | report folder (default `reports/`) |

Credentials are optional and read from the environment:

```bash
export GITHUB_TOKEN=ghp_…        # higher GitHub limits + private-org visibility
export HIBP_API_KEY=…            # HaveIBeenPwned breach feed
export MIRSAD_BREACH_DIR=~/dumps # local breach corpus (plain or .gz)
export MIRSAD_HOME=~/.mirsad     # cache location (default ./.mirsad)
```

---

## How a scan actually works

### 1. One verdict engine for every source

A site definition is a request plus a way to read the answer:

```json
{
  "id": "github", "kind": "username", "domain": "github.com",
  "probe": "https://www.github.com/{}",
  "check": { "mode": "two_marker",
             "exists":  {"code": 200, "text": ""},
             "missing": {"code": 404, "text": ""} },
  "tier": 1, "sources": ["mailaccess", "whatsmyname", "sherlock"]
}
```

`core/detect.py` turns the response into `found / not_found / unknown / blocked`
with a confidence score. The rules, in order:

1. **429 / 5xx** → `unknown` (provider problem, never a verdict)
2. **WAF challenge body** → `blocked`
3. **Parked domain / redirect stub** → `unknown`
4. **Two markers** → the existence rule decides; if both markers appear in a small
   JSON payload (Figma-style enum lists) it is `unknown`, and when the absence marker
   is strictly more specific than the presence marker, absence wins
5. **Status mode** → 2xx is only a hit if the identifier actually appears in the
   `<title>`/`og:title`/JSON body — this kills the "Bitchute echoes every path" class
   of false positive
6. **Message mode** → error marker means absent; otherwise the same content check
7. **Search/root URLs** (`/search?q=`, `/users/filter?search=`) can never prove an account

### 2. Email hits are verified against a control address

For every email hit, MIRSAD probes a random address **at the same domain**
(`mirsad<random>@domain`). If the control also "exists", the site answers uniformly
(catch-all or broken endpoint) and the hit is downgraded. This single mechanism
removed every false positive found during testing — Etsy, Figma, Replit, Chess and
X/Twitter all answered "taken" for a non-existent address before verification.

### 3. Branching (the Sylva idea)

```
email ──► accounts (216 services) ──► domain ──► DNS / SPF / DMARC
      └─► Google (gxlu) ──► breaches (HIBP + stealer logs + local dumps)

username ──► 4,577 platforms ──► GitHub ──► commit emails ──► email sweep (--expand)

domain ──► MX/SPF/DMARC ──► CT subdomains ──► harvested emails ──► email sweep
```

Depth and a branch budget (`--depth`, 25 nodes by default) keep a scan from exploding.

### 4. Scoring

Exposure is transparent — every point is listed in the report:

| Driver | Weight |
| --- | --- |
| Account footprint | up to 30 |
| High-value accounts (banking, cloud, social) | up to 15 |
| Breach exposure | up to 25 |
| Cleartext credentials / infostealer logs | +12 / +10 |
| Missing SPF / DMARC | +4 / +6 |
| Real name / phone / pastes | +4 / +5 / +5 |

A separate **credential risk** score (0–100) tracks passwords and stealer logs.

### 5. Output

- **HTML** — self-contained dark report: score gauge, driver list, force-directed
  identity graph, filterable findings table, JSON download. No CDN, works offline.
- **JSON** — every finding with confidence, reason, source and raw data.
- **CSV / Markdown** — for spreadsheets and tickets.

---

## Architecture

Deep dive: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · detection rules:
[docs/DETECTION.md](docs/DETECTION.md) · programmatic use:
[examples/library_usage.py](examples/library_usage.py).

```
mirsad/
├── cli.py                  argparse CLI, auto-detect, artefacts
├── config.py               tunables, API keys, paths
├── core/
│   ├── http.py             async client: semaphore, per-host bucket, retries, proxy, cache
│   ├── cache.py            SQLite response cache with per-entry TTL + negative caching
│   ├── detect.py           the verdict engine + profile extraction
│   ├── precheck.py         CSRF / cookie bootstrap (MailAccess technique)
│   ├── sites.py            corpus loader + filtering (tier / category / exclude)
│   ├── models.py           Finding, EntityGraph, Report, base-domain dedupe
│   ├── scoring.py          exposure + credential risk
│   ├── orchestrator.py     queue, branching, budgets
│   └── ui.py               rich progress + summary
├── modules/
│   ├── base.py             request builder, handler registry, worker pool
│   ├── username.py         4,577 platform sweep
│   ├── email_accounts.py   email sweep + control-address verification
│   ├── email_handlers.py   17 bespoke JSON/CSRF probes
│   ├── google.py           gxlu oracle
│   ├── github.py           profile, orgs, keys, repos, commit identities
│   ├── breach.py           HIBP, HudsonRock, local dumps
│   ├── domain.py           DNS (UDP + DoH fallback), SPF/DMARC, CT, harvest
│   └── patterns.py         permutations + 383k-domain company pattern index
├── report/                 html.py, export.py
└── data/                   sites.json (4,793 defs), disposable domains, pattern index
```

Design rules that kept it honest:

- **One schema.** Every source becomes the same `Finding`; the report never branches
  on where a fact came from.
- **Confidence is earned.** Two-marker hits score 0.96; a 200 status scores 0.78; an
  identifier that isn't echoed in the content scores 0.0 and is reported as unknown.
- **Failures are cached, not retried.** A dead host costs 8 seconds once, then one hour
  of silence. Cold 128-site scan: ~11s. Warm: ~2s.

---

## Tests

```bash
pytest -q      # 25 tests: detector rules, dedupe, data integrity, report rendering
```

The detector tests encode the false-positive classes that were found and fixed:
collision markers, ambiguous JSON enums, WAF pages, parked domains, redirect stubs,
search URLs and path-echo pages.

---

## Legal & ethics

MIRSAD queries **publicly reachable endpoints** and public APIs. It does not
authenticate, brute-force, or bypass a login. Email-existence checks use the same
signup/recovery endpoints a browser uses, and never send a message to the target.

Use it only on identities you own or have written permission to investigate.
Depending on your jurisdiction, unauthorised profiling can violate GDPR, CFAA and
local equivalents. The author accepts no liability for misuse.

---

## Credits

Detection logic is original; the *ideas* and corpora come from the projects in the
table above, each under its own licence (MIT / GPL / AGPL). If you redistribute
MIRSAD with a rebuilt database, keep those projects' attributions.

---

## Author

**0xHsn** · [GitHub @OxHsn](https://github.com/OxHsn) · [Instagram Y.ut](https://instagram.com/Y.ut)

OSINT researcher. Built MIRSAD as a single answer to "which of these eleven tools
do I run first?".

If MIRSAD saves you time, a star on the repo is the whole payment.

## License

MIT © 2026 0xHsn — see [LICENSE](LICENSE).

Use it only on identities you own or have written permission to investigate.
See [SECURITY.md](SECURITY.md) for the data-handling and disclosure policy.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR — the short version:
every fact is a `Finding`, confidence must be earned, and a new platform definition
needs proof that it discriminates (a claimed value and a random value that behave
differently). The detector tests in `tests/test_detect.py` are the regression suite
for every false-positive class we have met.

## Roadmap

- [ ] Phone module (carrier / line type / linked accounts)
- [ ] Face-check on GitHub avatars (Eyes' Venom idea, opt-in)
- [ ] STIX 2.1 + Maltego export
- [ ] Web UI (FastAPI + the same engine)
- [ ] Definition health checks: probe each site with a known-claimed and a
      known-unclaimed value, quarantine the ones that can no longer discriminate
