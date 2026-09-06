# DevNull

DevNull is a Python CLI that automates the early, repetitive stages of an
**authorized** web application security assessment: crawling, JavaScript
analysis, form/parameter mapping, and a set of low-risk checks that surface
*candidate* issues (missing headers, reflected-XSS leads, IDOR-shaped
parameters, open-redirect leads, SSRF-shaped parameters, exposed
sensitive files, etc.) for a human tester to validate.

It is a **lead generator**, not an exploit tool. It deliberately does not
attempt exploitation, confirm impact, or bypass authentication/WAFs — every
finding is written with an explicit "Manual validation" checklist and is
meant to be triaged by a person in Burp Suite (or similar) before being
reported anywhere.

> ⚠️ **Only run this against systems you own or are explicitly authorized to
> test.** Unauthorized scanning of third-party systems may be illegal in your
> jurisdiction. See [Legal / Scope](#legal--scope) below.

## Why this exists

Most of a web pentest's first day is mechanical: crawl the site, pull out
every JS file and grep it for endpoints and secrets, list every form and
parameter, check the boring stuff (security headers, cookie flags, CORS,
verbose errors, exposed `.env`/`.git`), and note which parameters *look*
interesting for XSS/IDOR/SSRF/open-redirect/SQLi follow-up. DevNull automates
that pass so a human can spend their time on the parts that actually need
judgement.

## Features

- **Crawler** — same-origin BFS crawl, extracts links, forms, and script tags
- **JS analysis** — pulls endpoint-shaped strings and flags likely hardcoded
  secrets/API keys, while filtering out common vendor bundles (jQuery,
  Bootstrap, React, etc.) to cut noise
- **Context-aware reflected-XSS pipeline** — sends a unique marker per input
  point, classifies *where* it lands (HTML body, HTML attribute, JS string,
  JSON), then follows up with a context-appropriate payload and scores
  confidence instead of pattern-matching blindly
- **Candidate finders** — IDOR-shaped identifiers, SSRF-shaped parameters,
  open-redirect parameters (tested safely against `example.com`), SQL
  error-message triggers, upload surfaces, auth/admin routes
- **Passive checks** — missing security headers, cookie flags
  (`Secure`/`HttpOnly`/`SameSite`), permissive CORS, risky HTTP methods
  (`TRACE`/`OPTIONS`), common sensitive-file exposure (`.env`, `.git/config`,
  backups, `phpinfo.php`, …), debug/stack-trace leakage
- **Optional browser recon** (Playwright) — renders the page, safely clicks
  non-destructive links/buttons (skips anything that looks like
  delete/logout/pay/submit), fills text-like inputs with a benign marker to
  catch DOM-based reflection, and screenshots what it finds
- **Reporting** — every run produces a Markdown report, a plain-text PoC
  report, per-finding Burp note files, and raw JSON (`findings.json`,
  `request-log.json`, `forms.json`, `technologies.json`) for scripting on top
  of the results
- **Scope enforcement** — the HTTP client refuses to send any request outside
  the target's base domain/subdomains, logging it as blocked instead
- **Rate limiting** — configurable delay between requests (default 0.8s)

## Installation

```bash
git clone https://github.com/<your-username>/devnull.git
cd devnull
pip install -r requirements.txt

# Optional, only needed for --browser mode:
playwright install chromium
```

Requires Python 3.9+.

## Usage

```bash
# Run everything
python3 devnull.py --target https://example.com --all

# Pick specific modules
python3 devnull.py --target example.com --enum --headers --cookies --cors

# Include browser-based recon (needs Playwright + Chromium installed)
python3 devnull.py --target https://example.com --enum --xss --browser

# Run the built-in test suite
python3 devnull.py --self-test
```

### Useful flags

| Flag | Purpose |
|---|---|
| `--target` | Authorized target URL or domain (required) |
| `--all` | Run every module |
| `--enum` | Crawl + JS analysis + endpoint detection |
| `--xss` | Context-aware reflected XSS pipeline |
| `--idor` / `--ssrf` / `--redirect` / `--sqli-errors` | Candidate finders |
| `--headers` / `--cookies` / `--cors` / `--methods` | Passive misconfiguration checks |
| `--sensitive-files` | Probe common sensitive paths |
| `--browser` / `--headed` | Playwright-based recon (headless by default) |
| `--rate` | Delay between requests in seconds (default `0.8`) |
| `--max-pages` | Crawl page limit (default `50`) |
| `--workspace` | Output directory (default `devnull-workspace`) |

Run `python3 devnull.py --help` for the full list.

### Output

Everything is written under `<workspace>/reports/<domain>/`:

```
reports/<domain>/
├── report.md              # Human-readable findings report
├── poc.txt                # Plain-text PoC-style report
├── findings.json          # Structured findings with fingerprints
├── request-log.json       # Full audit trail of every request sent
├── urls.txt / js-files.txt / api-endpoints.txt / params.txt
├── forms.json / technologies.json
├── burp-notes/            # One file per finding, ready to paste into Burp
└── screenshots/           # From --browser mode
```

## How it decides what's worth reporting

Findings carry both a **severity** (impact if confirmed) and a
**confidence** (how sure DevNull is that the signal is real) rather than
collapsing both into one score. For XSS specifically, a small pipeline does:

1. Send a baseline request, then a unique marker payload
2. If the marker reflects, classify the surrounding context (HTML body vs.
   attribute vs. inline `<script>` vs. JSON)
3. Fire a context-appropriate follow-up payload only into contexts where
   that payload class would matter
4. Score confidence from reflection + context + encoding state, and drop
   anything that scores `Low`

Findings are deduplicated by a fingerprint of `(category, normalized URL,
discriminating evidence field)`, so the same underlying issue reached via
different query strings collapses into one entry instead of flooding the
report.

## Legal / Scope

DevNull enforces **domain scope** at the HTTP client level — it will not send
a request to any host outside the target's base domain or its subdomains,
and logs the attempt as blocked if something tries to. That is a safety net,
not a substitute for authorization.

You are responsible for having written permission (a signed scope of work,
bug bounty program terms, or ownership of the target) before pointing this
at anything. Nothing in this tool confirms authorization on your behalf.

## Limitations

- All findings are *candidates* — this tool does not confirm exploitability
- No authentication handling (login flows, session tokens) is built in yet
- JSON/header/cookie-based input points aren't tested yet (only query string
  and form fields)
- Heuristic context detection (regex-based) can misclassify unusual markup

## License

MIT — see [LICENSE](LICENSE).
