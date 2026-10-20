# Secure Implementation Reference

This document maps each of the six vulnerabilities reproduced in the vulnerable
application (`app/app.py`) to the production-grade fix applied in the hardened
application (`app/secured/app_secure.py`). It is the companion reference to
[EXPLOITS.md](EXPLOITS.md) (how each flaw is attacked) and
[SCANNER.md](SCANNER.md) (how each fix is validated).

The hardened app shares the same SQLAlchemy models (`app/models.py`) and the
same templates layout, so every difference below is a deliberate security
control rather than a change in functionality.

---

## VULN-001 — SQL Injection (A03:2021)

**Vulnerable** (`app/app.py`, `/products`): the search term is concatenated
directly into a raw SQL string.

```python
sql = f"SELECT * FROM products WHERE name LIKE '%{search}%'"
result_rows = db.session.execute(text(sql)).fetchall()
```

**Hardened** (`app/secured/app_secure.py`, `/products`): the search is expressed
through the SQLAlchemy ORM, which parameterizes the value.

```python
query = Product.query
if search:
    query = query.filter(Product.name.like(f'%{search}%'))
results = query.all()
```

The `%` wildcards are part of a bound parameter, so input such as
`' OR '1'='1` is treated as a literal search string rather than SQL.

---

## VULN-002 — Stored XSS (A03:2021)

**Vulnerable** (`app/templates/product_detail.html`): review text is rendered
through Jinja2's `|safe` filter, disabling auto-escaping.

**Hardened** (`app/secured/templates/product_detail.html`): the `|safe` filter
is removed, so Jinja2's automatic contextual output encoding applies and
`<script>` payloads render as inert text.

---

## VULN-003 — IDOR (A01:2021)

**Vulnerable** (`app/app.py`, `/order/<id>`): any authenticated user can load
any order by changing the ID — there is no ownership check.

**Hardened** (`app/secured/app_secure.py`, `/order/<id>`): the resource owner is
verified, admins are allowed, and unauthorized attempts are logged.

```python
order = Order.query.get_or_404(order_id)
if order.user_id != current_user.id and not current_user.is_admin:
    app.logger.warning(f'Unauthorized access attempt: User {current_user.id} ...')
    abort(403)
```

---

## VULN-004 — Weak Password Hashing (A02:2021)

**Vulnerable** (`app/app.py`, `/login` and `/register`): passwords are stored as
unsalted MD5, which is crackable in seconds.

```python
password_hash = hashlib.md5(password.encode()).hexdigest()
```

**Hardened** (`app/secured/app_secure.py`): passwords are verified with bcrypt,
which is salted and deliberately slow (cost factor 12).

```python
if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
    login_user(user)
```

The scanner confirms this difference via login timing: the vulnerable app
verifies in a few milliseconds, the hardened app in ~250 ms (see
[SCANNER.md](SCANNER.md), Phase 6).

---

## VULN-005 — Missing CSRF Protection (A01:2021)

**Vulnerable**: state-changing POST forms (login, register, cart, checkout)
carry no anti-CSRF token.

**Hardened** (`app/secured/app_secure.py`): Flask-WTF's `CSRFProtect` is enabled
application-wide and every POST form includes a token.

```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```

```html
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
```

The session cookie is also set to `SameSite=Lax` as defense in depth.

---

## VULN-006 — Missing Security Headers (A05:2021)

**Vulnerable**: responses carry none of the standard defense-in-depth headers.

**Hardened** (`app/secured/app_secure.py`, `@app.after_request`): five headers
are applied to every response.

| Header | Value |
|--------|-------|
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-Content-Type-Options` | `nosniff` |
| `X-XSS-Protection` | `1; mode=block` |
| `Content-Security-Policy` | `default-src 'self'; ...` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |

`Strict-Transport-Security` is intentionally left commented out: HSTS only
applies over HTTPS and is ignored by browsers on the plain-HTTP local
deployment this project targets. The scanner treats HSTS as not-applicable for
this reason and only flags missing *core* headers (see
[SCANNER.md](SCANNER.md), Phase 5).
