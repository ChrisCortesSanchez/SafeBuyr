# Scanner Usage & Phase Breakdown

`scanner/vulnerability_scanner.py` is a custom black-box scanner that assesses a
running target over HTTP across eight sequential phases, then emits a timestamped
HTML and text report. See [SECURITY.md](SECURITY.md) for the fixes it validates
and [EXPLOITS.md](EXPLOITS.md) for the matching manual exploits.

---

## Usage

The target application must already be running (see the main
[README](../README.md) for how to launch each app).

```bash
# Scan the vulnerable version
python scanner/vulnerability_scanner.py http://localhost:5001

# Scan the hardened version
python scanner/vulnerability_scanner.py http://localhost:5002
```

Reports are written to `docs/` as `security_report_<UTC-timestamp>.html` and
`.txt`. Representative outputs for both apps are committed under
[`examples/reports/`](../examples/reports/).

---

## Phases

| Phase | Name | What it does |
|-------|------|--------------|
| 1 | Endpoint Discovery | Crawls a list of common paths, records reachable endpoints, and counts forms. |
| 2 | SQL Injection Detection | Sends injection payloads to `/products?search=` and compares the number of returned product cards against a normal query. |
| 3 | XSS Detection | Submits script payloads via product reviews and checks whether they are reflected unescaped. |
| 4 | IDOR Detection | Attempts to read `/order/<id>` resources the current user does not own. |
| 5 | Security Headers Analysis | Audits response headers; flags a finding only when a *core* header (X-Frame-Options, X-Content-Type-Options, Content-Security-Policy) is missing. |
| 6 | Authentication Testing | Infers password-hash strength from login timing (fast hash ⇒ weak), and probes the login form for SQL-injection bypass. |
| 7 | CSRF Detection | Inspects state-changing (POST) forms for an anti-CSRF token; GET forms such as search are ignored. |
| 8 | Report Generation | Aggregates findings into a risk score and writes the HTML/text reports. |

### Note on Phase 5 (headers)

`Strict-Transport-Security` is deliberately **not** required: HSTS only applies
over HTTPS and is ignored on plain-HTTP localhost. Only missing core headers
raise a finding, so a hardened app that omits HSTS by design scores clean.

### Note on Phase 6 (hashing)

Hash strength is measured by timing failed logins for a valid username. bcrypt
at cost 12 takes ~250 ms to verify, while unsalted MD5 completes in a few
milliseconds; a median verification time below the threshold is reported as
weak hashing. To reach the verification path on the hardened app, the scanner
first fetches a valid CSRF token.

---

## Risk Scoring

Each finding contributes a weight by severity; the risk score is their sum,
displayed on a 0–100 scale:

| Severity | Weight |
|----------|--------|
| CRITICAL | 10 |
| HIGH | 5 |
| MEDIUM | 2 |
| LOW | 1 |

The score maps to a band:

| Band | Score |
|------|-------|
| CRITICAL RISK | > 50 |
| HIGH RISK | 21 – 50 |
| MEDIUM RISK | 6 – 20 |
| LOW RISK | 0 – 5 |

---

## Current Results

Scanning both applications on their default ports produces:

| | Findings | Risk score | Band |
|-|----------|-----------|------|
| Vulnerable (`:5001`) | 6 (1 CRITICAL, 4 HIGH, 1 MEDIUM) | 32/100 | HIGH RISK |
| Hardened (`:5002`) | 0 | 0/100 | LOW RISK |

The hardened implementation eliminates every finding the scanner detects — a
100% reduction in risk score (32 → 0).
