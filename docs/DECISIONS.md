# Decision Log

One entry per non-obvious choice: what was picked, what was rejected, and why.
This is the interview material for the project — every "why did you do it that
way?" should be answerable from a row here. Newest entries at the top.

---

## 2026-10-23 — Branch protection on `main` (ruleset) + Dependabot alerts

**Picked:** A GitHub **ruleset** targeting the **default branch** (`main`) only:

- **Require status checks to pass:** Code Quality Checks, Regression Tests,
  Docker Build Test, Scanner Validation.
- **Bypass list empty** — the rule applies to the owner too; no admin override.
- **Dependabot alerts: On** (Dependency graph on).
- **Verified by a failing-check PR:** a branch with a deliberately broken
  regression test (`status_code == 999`) was opened as a PR; the red
  **Regression Tests** check **disabled the merge button**. Screenshot kept as
  Phase 0 evidence.

**Rejected / deferred:**

- **Ruleset targeting all branches** — rejected. It blocks pushing a failing
  commit to *any* branch, so you can't even open a PR to demonstrate the gate.
  Scoping to the default branch keeps feature branches free for WIP while still
  gating merges into `main`.
- **CodeQL code scanning** — deferred to Phase 1, where Semgrep SARIF is wired
  into GitHub code scanning; CodeQL default setup can be added alongside then.

**Caveat:** requiring **Code Quality Checks** as a gate is cosmetic — that job
runs `black`/`flake8`/`bandit` with `|| true`, so it always exits 0 and can
never fail a PR. The real gate is **Regression Tests**. Revisit when Phase 1/2
make the quality/security linters blocking.

**Why:** An empty bypass list is what actually makes the rule bite for a solo
owner — without it, admins (i.e. you) merge straight through failing checks,
which is the gotcha that made the first attempt look like it "didn't work."

---

## 2026-10-21 — Harden the two remaining bugs in the "hardened" app

**Picked:** In `app/secured/app_secure.py`, validate the login `next` parameter
with `is_safe_redirect_target()` (same-site relative paths only) and set
`debug=False`.

**Rejected:** Leaving the open redirect (CWE-601) and `debug=True` (CWE-489) in
the app that is supposed to be the secure reference.

**Why:** The hardened profile is the project's claim of "correct" and the oracle
the scanner is measured against; a flaw in it undermines every comparison. Both
remain intentionally present in the vulnerable profile as VULN-008 and VULN-009.

---

## 2026-10-20 — Fixed ports 5001 (vulnerable) and 5002 (hardened)

**Picked:** Hard-code 5001 and 5002; run each app as a module
(`python -m app.app`, `python -m app.secured.app_secure`).

**Rejected:** A `--port` flag / Flask's default 5000.

**Why:** Both versions must run simultaneously for side-by-side scanning, so
they need distinct fixed ports; 5000 is avoided because macOS AirPlay and other
tools commonly occupy it. Module execution is required because the apps use
package-relative imports (`from app.models import db`).

---

## 2026-10-20 — Upgrade Flask to 3.1.x; drop flask-jwt-extended

**Picked:** `Flask==3.1.0`, `Werkzeug==3.1.4`. Removed `flask-jwt-extended`.

**Rejected:** The previous `Flask==2.3.0` pin.

**Why:** The repo's interpreter is Python 3.14, which removed
`pkgutil.get_loader`; Flask 2.3 crashed on import. Flask 3.1.x is the first
line compatible. `flask-jwt-extended` was unused and caps Flask at `<3.0`, so it
had to go.

---

## Open items

- **CodeQL / GitHub code scanning** — not yet enabled; deferred to Phase 1 (see
  the 2026-10-23 entry).
