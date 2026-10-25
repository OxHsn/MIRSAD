# Contributing to MIRSAD

Thanks for wanting to improve MIRSAD. This project is a single Python package
with a strict internal contract, so a few rules keep it coherent.

## Setup

```bash
git clone https://github.com/OxHsn/mirsad.git && cd mirsad
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

## The one rule that matters

**Every fact is a `Finding`.** Modules do not invent their own result types.
If a new source returns something, it becomes:

```python
Finding(
    module="yoursource",
    kind="account",          # account | profile | breach | dns | identity | paste | note
    platform="Example",
    identifier=target,
    status=FOUND,            # found | not_found | unknown | blocked | error | info
    confidence=0.9,          # earned, see below
    url="https://example.com/alice",
    data={"domain": "example.com", ...},
    source="yoursource",
)
```

`data["domain"]` is what de-duplicates accounts across sources — always set it
when the fact belongs to a website.

## Adding a platform

1. **Declarative** — most sites need nothing but a definition. Add it to
   `tools/curated_email.py` (email) or extend `tools/build_data.py` (username),
   then rebuild:

   ```bash
   python tools/fetch_sources.py     # first time only
   python tools/build_data.py
   ```

2. **Bespoke handler** — when the answer lives in JSON logic, a CSRF dance or a
   two-step token flow, write a handler in `mirsad/modules/email_handlers.py`:

   ```python
   @handler("myservice")
   async def myservice(fetcher, site, email):
       resp = await fetcher.post("https://api.example.com/exists",
                                 payload={"email": email})
       data = _json(resp)
       if data.get("taken") is True:
           return _r(FOUND, 0.9, "myservice_taken", "https://example.com/")
       if data.get("taken") is False:
           return _r(NOT_FOUND, 0.85, "myservice_available")
       return _r(UNKNOWN, 0.0, "myservice_inconclusive")
   ```

   Handlers must never raise. Return `UNKNOWN` when the answer is ambiguous.

## Confidence rules

Confidence is a promise to the user, not decoration.

| Situation | Range |
| --- | --- |
| Two independent markers agree | 0.90 – 0.96 |
| Explicit JSON boolean from the provider | 0.85 – 0.92 |
| Status code + identifier echoed in content | 0.75 – 0.80 |
| Weak/derived signal (PGP key, third-party stats) | 0.60 – 0.75 |
| Anything ambiguous | 0.0 and status `UNKNOWN` |

Never return `FOUND` because a page returned 200. Prove it.

## False positives

Before adding a definition, test it with **two** values: a known-claimed one and
a random one that cannot exist. If both come back "found", the endpoint does not
discriminate and the definition belongs in `VERIFIED_BROKEN` in
`tools/build_data.py`, with the date and the reason.

## Tests

```bash
pytest -q
```

Add a detector test whenever you fix a false positive — `tests/test_detect.py`
is the regression suite for every class of noise we have met so far.

## Style

- Python 3.10+, type hints on public functions.
- No new runtime dependency without a very good reason (httpx + dnspython + rich
  is the whole budget).
- Keep modules free of global state; everything hangs off `Settings` and `Fetcher`.

## Commits

```
feat(module): add X probe
fix(detect): ignore path-echo pages
docs(readme): clarify tiers
```

## Legal

Contributions must query only publicly reachable endpoints, must not bypass
authentication, and must not add functionality whose primary purpose is
harassment or unauthorised access.
