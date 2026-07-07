# SAST-Gated Flask API

[![SAST](https://github.com/Hudec23/sast-gated-flask-api/actions/workflows/sast.yml/badge.svg)](https://github.com/Hudec23/sast-gated-flask-api/actions/workflows/sast.yml)
[![Secrets](https://github.com/Hudec23/sast-gated-flask-api/actions/workflows/secrets.yml/badge.svg)](https://github.com/Hudec23/sast-gated-flask-api/actions/workflows/secrets.yml)

Intentionally vulnerable Flask webshop API for DevSecOps portfolio work. Phase 1 delivers the app with planted bugs; Phase 2 adds Semgrep + Bandit gating; Phase 3 adds Gitleaks secrets scanning (pre-commit + CI).

**Pipeline status on `main`:** SAST workflow is expected to **FAIL** (deliberate vulns). Secrets workflow is expected to **PASS** (V04 allowlisted). See [SECURITY.md](SECURITY.md), [NOTES.md](NOTES.md), and [SECRETS.md](SECRETS.md).

**Do not deploy this application publicly.** Every vulnerability is deliberate and documented for SAST training.

## Quick start

```bash
uv sync
uv run flask --app webshop:create_app run --debug
```

The API listens on `http://127.0.0.1:5000`. SQLite data is created automatically at `data/webshop.db`.

## API reference

| Method | Path | Params / body | Safe? |
|--------|------|---------------|-------|
| GET | `/health` | — | Yes |
| GET | `/products` | — | Yes (parameterized SQL) |
| GET | `/products/search` | `?q=` | **V01** SQL injection |
| GET | `/products/<id>` | path `id` | **V02** SQL injection |
| GET | `/products/preview` | `?url=` | **V08** SSRF |
| GET | `/search/render` | `?q=` | **V09** reflected XSS |
| GET | `/orders/<id>` | path `id` | **V07** IDOR |
| POST | `/pricing/calculate` | `{"base_price", "formula"}` | **V03** eval |
| POST | `/pricing/eval-direct` | `{"expr"}` | **V13** direct-pattern eval |
| GET | `/admin/debug` | — | **V04** secret leak |
| POST | `/admin/reindex` | `{"index_name"}` | **V05** command injection (pattern) |
| POST | `/admin/export` | `{"archive_name"}` | **V14** multi-hop taint subprocess |
| GET | `/files/<path>` | path `filepath` | **V06** path traversal |
| POST | `/session/restore` | `{"session_data"}` | **V10** pickle |
| GET | `/login/redirect` | `?next=` | **V11** open redirect |
| POST | `/auth/check` | `{"email", "password"}` | **V12** weak MD5 hash |

## Vulnerability index

Find all markers in source:

```bash
grep -rn "VULN:" src/webshop/
```

| ID | Endpoint | Bug | OWASP | Location | Example payload |
|----|----------|-----|-------|----------|-----------------|
| V01 | `GET /products/search?q=` | SQL injection via f-string | A03 Injection | `routes/products.py` | `?q=' OR 1=1--` |
| V02 | `GET /products/<id>` | SQL injection via concatenated id | A03 Injection | `routes/products.py` | `/products/1 OR 1=1` |
| V03 | `POST /pricing/calculate` | `eval()` on user formula | A03 Injection | `routes/pricing.py` | `{"base_price":100,"formula":"__import__('os').system('id')"}` |
| V04 | `GET /admin/debug` | Hardcoded secrets in response | A02 / A05 | `config.py`, `routes/admin.py` | `curl /admin/debug` |
| V05 | `POST /admin/reindex` | `subprocess` with `shell=True` | A03 Injection | `routes/admin.py` | `{"index_name":"x; id"}` |
| V06 | `GET /files/<path>` | Path traversal | A01 Broken Access Control | `routes/admin.py` | `/files/../../etc/passwd` |
| V07 | `GET /orders/<id>` | IDOR — no ownership check | A01 Broken Access Control | `routes/orders.py` | `/orders/1` (any user's order) |
| V08 | `GET /products/preview?url=` | SSRF with `verify=False` | A10 SSRF | `routes/products.py` | `?url=http://169.254.169.254/` |
| V09 | `GET /search/render?q=` | Reflected XSS in HTML | A03 Injection | `routes/products.py` | `?q=<script>alert(1)</script>` |
| V10 | `POST /session/restore` | `pickle.loads()` on untrusted data | A08 Integrity | `routes/auth.py` | base64-encoded pickle payload |
| V11 | `GET /login/redirect?next=` | Open redirect | A01 Broken Access Control | `routes/auth.py` | `?next=https://evil.com` |
| V12 | `POST /auth/check` | MD5 password comparison | A02 Crypto Failures | `routes/auth.py` | `{"email":"alice@example.com","password":"hello"}` |
| V13 | `POST /pricing/eval-direct` | One-line `eval(request input)` | A03 Injection | `routes/pricing.py` | `{"expr":"2+2"}` |
| V14 | `POST /admin/export` | Multi-hop taint → `subprocess` (no shell) | A03 Injection | `routes/admin.py` | `{"archive_name":"x;id"}` |

### Sample curl commands

```bash
# Safe baseline
curl http://127.0.0.1:5000/health
curl http://127.0.0.1:5000/products

# V01 — SQL injection in search
curl "http://127.0.0.1:5000/products/search?q=' OR 1=1--"

# V03 — eval in pricing
curl -X POST http://127.0.0.1:5000/pricing/calculate \
  -H "Content-Type: application/json" \
  -d '{"base_price": 100, "formula": "base_price * 0.9"}'

# V04 — leaked secrets
curl http://127.0.0.1:5000/admin/debug

# V07 — IDOR on orders
curl http://127.0.0.1:5000/orders/1

# V12 — weak auth (demo user: alice@example.com / hello)
curl -X POST http://127.0.0.1:5000/auth/check \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "hello"}'
```

## Project structure

```
src/webshop/
├── __init__.py      # create_app() factory
├── config.py        # hardcoded secrets (V04)
├── db.py            # SQLite schema + seed data
└── routes/
    ├── health.py    # safe baseline
    ├── products.py  # V01, V02, V08, V09
    ├── orders.py    # V07
    ├── pricing.py   # V03, V13
    ├── admin.py     # V04, V05, V06, V14
    └── auth.py      # V10, V11, V12
```

## Tests

```bash
uv run pytest
```

## SAST (local)

Same commands as CI — see [SECURITY.md](SECURITY.md) for findings and blind spots.

```bash
uv sync --dev

# Bandit — fails on Medium+ severity, Medium+ confidence
uv run bandit -r src/webshop -ll -ii

# Semgrep — fails on ERROR-severity findings
uv run semgrep scan \
  --config p/python \
  --config p/flask \
  --config p/security-audit \
  --config p/secrets \
  --config .semgrep/ \
  --severity ERROR \
  --error \
  src/webshop
```

## Secrets scanning (local)

Phase 3 — Gitleaks via pre-commit and CI. Full narrative: **[SECRETS.md](SECRETS.md)**

```bash
uv sync --dev
uv run pre-commit install          # once per clone
uv run pre-commit run gitleaks --all-files
```

Pre-commit blocks commits with staged secrets. CI scans **full git history** as a backstop (`git commit --no-verify` still fails on push).

## CI pipeline

### SAST — [`.github/workflows/sast.yml`](.github/workflows/sast.yml)

| Job | Tool | Gate |
|-----|------|------|
| `test` | pytest | Must pass |
| `bandit` | Bandit | `-ll -ii` (Medium+) |
| `semgrep` | Semgrep OSS | `--severity ERROR --error` |

### Secrets — [`.github/workflows/secrets.yml`](.github/workflows/secrets.yml)

| Job | Tool | Gate |
|-----|------|------|
| `gitleaks` | Gitleaks | Fail on any detected leak (`fetch-depth: 0`) |

## Security analysis

Full SAST narrative — tool rationale, findings mapped to V01–V14, blind spots, and production remediation: **[SECURITY.md](SECURITY.md)**

Pattern match vs taint tracking interview notes (V13/V14 paired demos): **[NOTES.md](NOTES.md)**

Secrets leak prevention — pre-commit vs CI, demo branch, history scrubbing: **[SECRETS.md](SECRETS.md)**

## License

MIT — see [LICENSE](LICENSE).
