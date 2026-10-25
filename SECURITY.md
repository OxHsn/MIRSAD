# Security policy

## Scope

MIRSAD is a **read-only reconnaissance tool**. It queries public endpoints and
public APIs. It does not authenticate, brute-force, exploit, or bypass a login.

That means the interesting security surface is:

- the HTTP client (SSRF-ish URLs coming from site definitions, TLS handling),
- the HTML report (a finding rendered into a browser),
- the local cache (responses may contain personal data).

## Reporting a vulnerability

Open a private security advisory on GitHub, or contact **[@OxHsn](https://github.com/OxHsn)** on GitHub or Instagram
(`Y.ut`). Please do not open a public issue for anything that could expose a
user's data.

Include: affected version, a minimal reproduction, and the impact you expect.
You will get an acknowledgement within 72 hours.

## Data handling

- The response cache lives in `./.mirsad/cache.db` and stores raw responses for
  24 hours (failures for 1 hour). Delete it with `mirsad cache --clear` or by
  removing the folder.
- Reports contain everything the scan found. Treat them as sensitive: they are
  written to `reports/` and are git-ignored by default.
- No telemetry. No phone-home. The only outbound traffic is the probes you ask
  for, plus DNS (UDP or DNS-over-HTTPS when UDP is blocked).

## Legal

Use MIRSAD only on identities you own or are authorised to investigate.
Unauthorised profiling can violate GDPR, the CFAA and local equivalents.
The author accepts no liability for misuse.
