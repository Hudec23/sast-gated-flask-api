# NOTES — Pattern Match vs Taint Tracking

Blog-style notes for interviews. This repo deliberately pairs vulnerabilities that **look** similar but behave differently under SAST tools.

See also: [SECURITY.md](SECURITY.md) (full findings), [README.md](README.md) (API index).

---

## The core idea

Not all static analysis is the same:

| Analysis style | What it does | Example tool behavior |
|----------------|--------------|------------------------|
| **Pattern / sink match** | Flags dangerous APIs when they appear in code | Bandit `B307` on any `eval()` call |
| **Taint / dataflow** | Tracks user input through assignments and function calls to a sink | Semgrep `tainted-sql-string`, custom `flask-tainted-subprocess-no-shell` |
| **Logic / authz** | Requires understanding application intent | Nothing catches V07 IDOR |

Running two scanners is table stakes. Understanding **why** one finds a bug and the other misses it is the interview story.

---

## Paired demos in this repo

### V13 — Direct pattern (both tools catch at CI threshold)

**Endpoint:** `POST /pricing/eval-direct`  
**Code:** `eval(data.get("expr", "0"))` — request input to `eval()` on **one line**.

```bash
curl -X POST http://127.0.0.1:5000/pricing/eval-direct \
  -H "Content-Type: application/json" \
  -d '{"expr": "2 + 2"}'
```

| Tool | Rule | Type |
|------|------|------|
| Bandit | **B307** | Pattern — flags `eval()` call site |
| Semgrep | `eval-detected` | Pattern — flags `eval()` call site |
| Semgrep | `eval-injection` | **Taint** — `request` → `eval()` |

Both tools fail CI. The Semgrep taint rule (`python.flask.security.injection.user-eval.eval-injection`) reinforces what Bandit already sees via pattern matching.

**Location:** `src/webshop/routes/pricing.py` — `# VULN: V13-DirectPattern`

---

### V14 — Multi-hop taint (Semgrep catches, Bandit misses at CI threshold)

**Endpoint:** `POST /admin/export`  
**Flow:** `request.json` → `_normalize_archive_name()` → `_build_archive_args()` → `subprocess.run(args, shell=False)`

No `shell=True`. No `eval()`. User input crosses **three hops** including a helper function.

```bash
curl -X POST http://127.0.0.1:5000/admin/export \
  -H "Content-Type: application/json" \
  -d '{"archive_name": "report; id"}'
```

| Tool | Rule | CI gate (`-ll -ii` / ERROR) | Type |
|------|------|------------------------------|------|
| Bandit | B603 | **No** (LOW severity) | Generic subprocess warning, no dataflow |
| Bandit | B602 | No (V05 uses `shell=True`, not this endpoint) | — |
| Semgrep | `flask-tainted-subprocess-no-shell` | **Yes** | Custom **taint** rule in [`.semgrep/tainted-subprocess.yml`](.semgrep/tainted-subprocess.yml) |

Bandit lists B603 on the `subprocess.run(..., shell=False)` line when run without severity filters, but it is LOW severity and does not trace taint — it fires on any non-shell subprocess call. At our CI threshold, **V14 is invisible to Bandit**.

Stock Semgrep community rules also miss V14. A **custom taint rule** tracks `request.json.get` → propagators → `subprocess.run($CMD, ...)` where `shell=True` is absent.

**Location:** `src/webshop/routes/admin.py` — `# VULN: V14-TaintOnly`

---

### V05 — Misleading multi-hop (both catch via pattern, not taint)

**Endpoint:** `POST /admin/reindex`  
**Flow:** `request.json` → `index_name` → f-string → `subprocess.run(command, shell=True)`

This *looks* like a multi-hop taint demo, but both tools catch **`shell=True` on the sink line** — a pattern match, not dataflow proof.

| Tool | Rule | Type |
|------|------|------|
| Bandit | **B602** | Pattern — `shell=True` |
| Semgrep | `subprocess-shell-true` | Pattern — `shell=True` |

Use V05 as a contrast: "multi-hop" alone does not explain tool divergence. The sink pattern dominates.

---

## Summary table

| ID | Style | Hops | Sink | Bandit (CI) | Semgrep (CI) | Lesson |
|----|-------|------|------|-------------|--------------|--------|
| V13 | Direct pattern | 1 | `eval(input)` | B307 | `eval-injection` + `eval-detected` | Obvious sinks — pattern rules suffice |
| V14 | Multi-hop taint | 3 | `subprocess.run(args, shell=False)` | — | `flask-tainted-subprocess-no-shell` | Need taint + often custom rules |
| V05 | Multi-hop + obvious sink | 2 | `subprocess.run(..., shell=True)` | B602 | `subprocess-shell-true` | Pattern on sink masks dataflow story |
| V01 | Multi-hop taint | 2 | SQL f-string | — (B608 low confidence) | `tainted-sql-string` | Stock Semgrep taint for Flask SQLi |
| V07 | Logic flaw | — | missing authz | — | — | SAST cannot replace authz review |

---

## Reproduce locally

```bash
uv sync --dev

# Bandit — note V14 absent, V13 present
uv run bandit -r src/webshop -ll -ii

# Semgrep — note V13 + V14 + stock rules
uv run semgrep scan \
  --config p/python \
  --config p/flask \
  --config p/security-audit \
  --config p/secrets \
  --config .semgrep/ \
  --severity ERROR \
  src/webshop

# V14 only — custom taint rule
uv run semgrep scan --config .semgrep/tainted-subprocess.yml src/webshop/routes/admin.py
```

---

## What I'd say in an interview

> "We ran Bandit and Semgrep with fail-red gating. Bandit is an AST walker — great for Python sinks like `eval` and `shell=True`, but it doesn't track request data through helper functions. Semgrep adds taint rules: stock rules caught our SQLi and SSRF, but multi-hop command injection without `shell=True` needed a custom rule. That's why V14 exists — to prove I understand the difference between pattern matching and dataflow analysis, and when to write custom Semgrep rules. V07 IDOR still slips through both — that's where you'd add integration tests or DAST."

---

## Custom rule reference

[`.semgrep/tainted-subprocess.yml`](.semgrep/tainted-subprocess.yml) — taint mode rule:

- **Sources:** `request.json.get`, `request.args.get`, etc.
- **Sinks:** `subprocess.run($CMD, ...)` where `shell=True` is not used
- **Propagators:** assignments and `return` statements (enough for this demo's helper chain)

In production, enable Semgrep Pro/CodeQL interfile analysis or expand propagators for class fields and cross-file flows.
