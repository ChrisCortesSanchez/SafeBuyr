# Ground Truth — Planted Vulnerability Inventory

This is the authoritative list of every vulnerability **intentionally** planted
in the vulnerable profile (`app/app.py` and its manifest), with the exact
location, classification, how it is detected, and the hardened fix that
eliminates it. It is the oracle against which scanner output and tool
comparisons are scored: a true positive is a finding that maps to a row here; a
false positive is one that does not; a false negative is a row no tool reported.

- **Scanner status** reflects the 8-phase scanner in `scanner/vulnerability_scanner.py`.
  `✅ detected` means a phase reports it today; `⏳ planned` means the row is
  ground truth awaiting a scanner phase (software-composition analysis,
  configuration review, redirect checks).
- Line numbers point at the vulnerable profile; see [SECURITY.md](SECURITY.md)
  for the corresponding hardened code.

| ID | Vulnerability | Location (vulnerable) | CWE | OWASP | Severity | Scanner | Hardened fix |
|----|---------------|-----------------------|-----|-------|----------|---------|--------------|
| VULN-001 | SQL injection in product search | `app/app.py` `/products?search=` | CWE-89 | A03:2021 | CRITICAL | ✅ Phase 2 | Parameterized queries via SQLAlchemy ORM |
| VULN-002 | Stored XSS via product reviews | `app/app.py` review rendering + `templates/*` `\|safe` | CWE-79 | A03:2021 | HIGH | ✅ Phase 3 | `\|safe` removed; automatic Jinja2 escaping; `bleach` sanitization |
| VULN-003 | IDOR on orders and cart | `app/app.py` order/cart endpoints | CWE-639 | A01:2021 | HIGH | ✅ Phase 4 | Ownership check against `current_user` on every resource |
| VULN-004 | Weak password hashing (MD5, unsalted) | `app/app.py:121-122` | CWE-916 | A02:2021 | HIGH | ✅ Phase 6 | bcrypt, cost factor 12 |
| VULN-005 | Missing CSRF protection | `app/app.py` state-changing forms | CWE-352 | A01:2021 | HIGH | ✅ Phase 7 | Flask-WTF CSRF tokens on all forms |
| VULN-006 | Missing security headers | `app/app.py` responses | CWE-693 | A05:2021 | MEDIUM | ✅ Phase 5 | 5/6 headers set (CSP, HSTS, X-Frame-Options, etc.) |
| VULN-007 | Hardcoded weak secret key | `app/app.py:21` | CWE-798 | A05:2021 | MEDIUM | ⏳ planned (config review) | `os.urandom(32)` per-process random key |
| VULN-008 | Vulnerable dependency (PyYAML 5.3.1, CVE-2020-14343) | `requirements.txt` | CWE-1104 | A06:2021 | HIGH | ⏳ planned (SCA phase) | Remove unused dep / upgrade to patched PyYAML ≥ 5.4 |
| VULN-009 | Open redirect via `next` parameter | `app/app.py:128-129` | CWE-601 | A01:2021 | MEDIUM | ⏳ planned (redirect check) | `is_safe_redirect_target()` allows same-site relative paths only |
| VULN-010 | Debug mode enabled in production | `app/app.py:430-433` | CWE-489 | A05:2021 | MEDIUM | ⏳ planned (config review) | `debug=False` in hardened app |

## Coverage summary

- **OWASP Top 10 categories:** A01, A02, A03, A05, A06 (5 of 10).
- **Detected by the current scanner:** VULN-001 through VULN-006 (6 of 10).
- **Ground truth awaiting a scanner phase:** VULN-007 through VULN-010 — these are
  the drivers for the next scanner expansion (SCA + configuration/redirect review).

## Notes

- `exploits/cmndi.py` is a **demonstration script only**: the vulnerable app has
  no command-execution sink, so command injection is **not** ground truth and is
  excluded from this table and the scorecard.
- The hardened profile (`app/secured/app_secure.py`) is expected to report
  **zero** of these rows; the regression suite in `tests/` enforces that each
  fix stays in place.
