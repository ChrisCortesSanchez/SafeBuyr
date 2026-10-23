# Decision Log

One entry per non-obvious choice: what was picked, what was rejected, and why.
This is the interview material for the project — every "why did you do it that
way?" should be answerable from a row here. Newest entries at the top.

---

## 2026-10-21 — Do **not** plant a vulnerable dependency as a ground-truth flaw

**Picked:** Keep `requirements.txt` on current, non-vulnerable pins. Ground
truth covers 9 application flaws (VULN-001…009); no software-composition (SCA)
row.

**Rejected:** Adding `PyYAML==5.3.1` (CVE-2020-14343) as VULN-008 to seed a
future SCA scanner phase.

**Why:** A vulnerable dependency is a one-line, low-skill plant and an even
easier fix (`pip install -U`), so it adds little evidence of security depth
compared with the injection/authz/crypto flaws already planted. It was also
*unreachable* (declared but never imported), which would have made it a weak,
arguably false-positive demo. If an SCA phase is added later, prefer pinning an
**already-used** package (e.g. `requests`) to a known-vulnerable version so the
finding is genuinely reachable. See [GROUND_TRUTH.md](GROUND_TRUTH.md).

---

## 2026-10-21 — Rename the project VulnHub → SafeBuyr

**Picked:** Replace every `VulnHub`/`vulnhub` mention with `SafeBuyr`/`safebuyr`
across code, scanner, exploits, docs, `docker-compose.yml` (service, container,
and network names), seed emails (`@safebuyr.*`), and example reports.

**Rejected:** Leaving legacy branding in banners/docstrings.

**Why:** The repo was renamed but stray legacy strings remained, which reads as
unfinished to anyone reviewing the project. `.db` files are not tracked and no
test asserts on email values, so the rename is safe and self-contained.

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

## Pending (GitHub-side, owner to confirm)

- **Branch protection on `main`** — optional for a solo project, but still worth
  enabling: it blocks accidental force-pushes and can require CI to pass before
  merge. This repo only uses `main`.
- **Dependabot alerts** and **GitHub code scanning** — free on public repos;
  enable in repo Settings → Security. These back the Phase 2 (SCA) and Phase 1
  (SAST) work later in the build plan.
