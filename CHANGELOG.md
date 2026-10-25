# Changelog

All notable changes to MIRSAD are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · [SemVer](https://semver.org/).

## [1.0.0] — 2026-10-25

First release. Eleven upstream projects merged into one engine.

### Added
- Unified verdict engine (`found` / `not_found` / `unknown` / `blocked`) with a
  written reason and a confidence score for every result.
- 4,577 username definitions and 216 email-existence definitions, merged from
  Sherlock, WhatsMyName and MailAccess, plus curated probes from holehe, Zehef
  and Eyes.
- Control-address verification for email hits (catch-all and broken-endpoint
  detection), enabled by default.
- Branching orchestrator: email → domain → DNS/breaches, username → GitHub →
  commit emails, with depth and branch budget.
- GitHub module: profile, orgs, SSH/GPG keys, repos and commit identities.
- Google identity oracle (`gxlu`) with no authentication.
- Breach module: HIBP (key), HudsonRock infostealer feed, local dump search
  (plain and `.gz`).
- Domain module: MX, SPF, DMARC, provider detection, disposable domains,
  certificate-transparency subdomains and website email harvesting.
- DNS-over-HTTPS fallback when UDP/53 is blocked.
- Exposure score (0–100) with per-driver breakdown, plus a separate credential
  risk score.
- Self-contained dark HTML report with a force-directed identity graph, filters
  and JSON download; JSON / CSV / Markdown exports.
- SQLite response cache with per-entry TTL and negative caching.
- 25 tests covering detector rules, de-duplication, data integrity and reports.

### Fixed during development
- Two-marker definitions whose payload lists both enum values (Figma-style) no
  longer report a hit.
- Path-echo pages (Bitchute) no longer produce a false positive for every input.
- Unbounded email regex caused 1.2 s/page on minified HTML; bounded quantifiers.
- Read timeouts are no longer retried; failures are cached for an hour.
- Subdomain merging no longer collapses `api.github.com` onto `github.com`.
