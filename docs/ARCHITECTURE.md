# Architecture

MIRSAD is one package with four layers. Each layer only knows about the one below it,
which is why 11 upstream projects could be merged without special cases leaking into
the CLI or the report.

```
┌──────────────────────────────────────────────────────────────┐
│  cli.py            argparse, auto-detect, artefacts          │
├──────────────────────────────────────────────────────────────┤
│  core/orchestrator.py   queue · branching · budget           │
│  core/scoring.py        exposure + credential risk           │
├──────────────────────────────────────────────────────────────┤
│  modules/*          username · email · github · breach ·     │
│                     domain · google · patterns               │
├──────────────────────────────────────────────────────────────┤
│  core/http.py       async client · semaphore · per-host      │
│  core/detect.py     verdict engine · profile extraction      │
│  core/cache.py      SQLite responses (TTL + negative cache)  │
│  core/sites.py      the 4,793-definition corpus              │
└──────────────────────────────────────────────────────────────┘
```

## Data model

Everything is a `Finding` (`core/models.py`). There is no per-source result type.

```python
Finding(
    module="github",          # which module produced it
    kind="account",           # account | profile | breach | dns | identity | paste | note
    platform="GitHub",
    identifier="torvalds",    # the value that was queried
    status="found",           # found | not_found | unknown | blocked | error | info
    confidence=0.96,
    url="https://github.com/torvalds",
    data={...},               # free-form, but always carries "domain" for accounts
    source="gitfive",
    tags=["coding", "high-value"],
)
```

`Report` owns the findings, an `EntityGraph`, the score and the run statistics.
`Report.dedupe()` collapses accounts that point at the same base domain, keeping the
copy with the higher confidence (and the better URL).

## Concurrency

`Fetcher` (`core/http.py`) is the only thing that touches the network:

- one `httpx.AsyncClient` per run, `max_connections = concurrency * 2`
- a global `Semaphore(concurrency)` caps in-flight requests
- a per-host token bucket (8 rps, burst 8) stops one site from being hammered when
  several definitions share a host
- retries only on connect/protocol errors; a **read timeout is final** and is cached
  as a failure for an hour, so a dead host costs 8 seconds once instead of every run
- the user agent rotates per request from a small pool

`run_sites()` (`modules/base.py`) is a bounded worker pool (`concurrency * 2` workers)
draining a queue, so progress can be reported per completed site.

Measured on 128 core sites: **~11 s cold, ~2 s warm**.

## Caching

`core/cache.py` stores `(status, final_url, body)` keyed by
`sha256(method | url | payload)`. Each row carries its own `expires`, so:

- successful responses: 24 h
- failures (timeout / connect error): 1 h, with `status = 0`

The cache is what makes iterative work pleasant: re-running a scan after changing the
report template costs nothing on the network.

Location: `./.mirsad/cache.db` (override with `MIRSAD_HOME`). Clear with
`mirsad cache --clear`.

## Branching

`core/orchestrator.py` runs a BFS over `(value, kind, depth)`:

```
email    → accounts (216) · google · breaches · domain
         → domain → DNS/SPF/DMARC → CT subdomains → harvested emails
username → 4,577 platforms → GitHub → commit emails        (needs --expand)
```

Two guards keep a scan bounded: `--depth` (default 1) and a branch budget of 25 new
nodes. Every enqueued node is de-duplicated by `(kind, lowercased value)`.

## Scoring

`core/scoring.py` is deliberately transparent: it returns a list of
`{label, points, detail, severity}` drivers, and the score is their capped sum. The
report renders the list verbatim, so a user can argue with the number instead of
guessing where it came from.

## Reports

`report/html.py` is a single f-string-free template (`.replace()` on `__TOKEN__`
placeholders) with the whole dataset embedded as `const DATA = {...}`. No CDN, no
build step, no network: the file works from a USB stick. The identity graph is a
small force simulation on a canvas (~120 lines of vanilla JS).

## Extending

| Goal | Where |
| --- | --- |
| Add a username platform | `tools/build_data.py` or a new upstream source |
| Add an email platform (declarative) | `tools/curated_email.py` |
| Add an email platform (JSON/CSRF logic) | `mirsad/modules/email_handlers.py` |
| Add a whole new module | `mirsad/modules/<name>.py`, dispatch in `orchestrator._dispatch` |
| Change what counts as "found" | `mirsad/core/detect.py` + a test in `tests/test_detect.py` |
| Change the report | `mirsad/report/html.py` |

The contract for a module is one function:

```python
async def investigate(fetcher, target, settings) -> list[Finding]
```

Nothing else is imported from it.
