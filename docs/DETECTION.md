# Detection rules

The hardest part of username/email enumeration is not sending the request — it is
deciding what the response means. Every tool in this space has its own answer, and
most of them are wrong for a meaningful fraction of sites.

MIRSAD normalises all of them into one function:

```python
classify(defn, status, body, final_url, needle, platform) -> Verdict(status, confidence, reason)
```

`reason` is always populated, so a result can be audited instead of trusted.

## The five modes

### 1. `two_marker` — WhatsMyName / MailAccess

The site tells you both answers explicitly:

```json
"check": {
  "mode": "two_marker",
  "exists":  {"code": 200, "text": "\"full_name\":"},
  "missing": {"code": 404, "text": "\"message\":\"No workspace"}
}
```

Rules, in order:

1. If the absence marker is *strictly more specific* than the presence marker
   (`e_string` is a substring of `m_string`), absence wins. Otherwise a "not found"
   body like `{"userId":0}` would match the presence marker `"userId":` and every
   miss would read as a hit.
2. If **both** markers appear in a small JSON payload (< 4 KB), the answer is
   `unknown`. APIs that list enum values (`["sign_in","sign_up"]`) match both and
   prove nothing — this is the Figma false positive.
3. Presence → `found` (0.96 with a text marker, 0.86 on status alone).
4. Absence → `not_found` (0.95 / 0.85).
5. Neither → `unknown`, with the reason `no_marker`.

### 2. `status` — Sherlock's simplest case

A 2xx is **not** proof. The rules:

- 429 / 5xx → `unknown` (provider problem)
- WAF challenge body → `blocked`
- parked-domain body → `unknown`
- tiny page whose only job is a redirect (`meta refresh`, `window.location`) → `unknown`
- URL is a site root or a search page → `unknown`
- the identifier must appear in `<title>`, `og:title`, `og:site_name`, or a JSON body;
  otherwise `unknown`

That last rule is what kills the "Bitchute echoes the requested path in a meta tag
for every input" class of false positive. A path echo is not a profile.

### 3. `message` — error text in the body

If an error marker is present → `not_found`. If a positive marker list is present,
all of them must match → `found`. Otherwise the identifier-echo rule applies.

### 4. `redirect` — the 404 is a redirect

Used with `follow_redirects: false`. A 2xx on the un-redirected probe is a hit.

### 5. `handler` — bespoke code

When the answer lives in JSON logic, a CSRF dance or a two-step token flow, a handler
in `modules/email_handlers.py` returns the same `Verdict` shape. 17 services need this.

## Confidence is a promise

| Situation | Range |
| --- | --- |
| Two independent markers agree | 0.90 – 0.96 |
| Explicit provider boolean (`"taken": true`) | 0.85 – 0.92 |
| Status code + identifier echoed in content | 0.75 – 0.80 |
| Derived / third-party signal | 0.60 – 0.75 |
| Ambiguous | 0.0, status `unknown` |

A `found` with confidence 0.78 is honest: it means "the page looks like a profile, but
the site did not confirm it". The report shows the number.

## Email-specific: the control address

Every email hit is re-probed with a random address **at the same domain**:

```
target : alice@company.com      → "taken"
control: mirsad3f9c…@company.com → "taken"   ⇒  catch-all / broken endpoint ⇒ unknown
                                 → "available" ⇒  genuine hit, confidence +0.03
```

This is the single highest-value rule in the project. It removed every false positive
found during development: Etsy, Figma, Replit, Chess and X/Twitter all answered
"taken" for an address that cannot exist.

Cost: one extra request per *hit*, not per site. Disable with `--no-verify`.

## Verifying a new definition

A definition is only mergeable if it discriminates. Test it twice:

```bash
# 1. a value that must exist
curl -s "<probe with a known-claimed username>" | grep -c "<exists marker>"

# 2. a value that cannot exist
curl -s "<probe with a random string>" | grep -c "<exists marker>"
```

Expected: `1` then `0`. If both are `1`, the endpoint does not discriminate — add it
to `VERIFIED_BROKEN` in `tools/build_data.py` with the date and the reason.

## Regression suite

`tests/test_detect.py` encodes every class of noise met so far:

- collision markers (`"userId":` vs `"userId":0`)
- ambiguous JSON enums
- WAF pages, parked domains, redirect stubs
- search / filter URLs
- path-echo pages
- identifier not present in content

Add a test whenever you fix a false positive. That file is the memory of the project.
