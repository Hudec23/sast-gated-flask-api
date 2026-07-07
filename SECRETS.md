# Secrets Leak Prevention — Phase 3

Git secrets scanning with **Gitleaks**: pre-commit (shift-left) + CI (backstop). Complements Phase 2 SAST ([SECURITY.md](SECURITY.md)) — different tool, different threat model.

**Do not commit real credentials.** Demo keys below are AWS documentation examples only.

---

## Why secrets scanning is not SAST

| | SAST (Bandit / Semgrep) | Gitleaks |
|--|-------------------------|----------|
| **Scans** | Source code patterns | Git blobs and commit history |
| **Catches** | `eval()`, SQLi, hardcoded strings in `.py` | `AKIA...` keys in `.env`, committed certs, tokens in any file |
| **V04 in `config.py`** | Bandit B105 (LOW, often filtered at CI) | Flags unless path-allowlisted |
| **Secret removed in later commit** | N/A | Still in history unless scrubbed |

Gitleaks answers: *"Did we ever commit a secret to git?"*  
SAST answers: *"Does this code use dangerous APIs or patterns?"*

---

## Pipeline overview

Workflow: [`.github/workflows/secrets.yml`](.github/workflows/secrets.yml)

```mermaid
flowchart TB
    subgraph local [Developer machine]
        Edit[Edit files]
        PreCommit[pre-commit gitleaks]
        Bypass["git commit --no-verify"]
    end

    subgraph ci [GitHub Actions]
        Checkout["checkout fetch-depth 0"]
        GitleaksCI[gitleaks-action]
    end

    Edit --> PreCommit
    PreCommit -->|leak in staged files| BlockLocal[Commit blocked]
    PreCommit -->|clean or allowlisted| CommitOK[Commit OK]
    Bypass --> Push[git push]
    Push --> Checkout --> GitleaksCI
    GitleaksCI -->|leak in history| FailCI[Workflow fails]
```

| Layer | Tool | Scope | Bypass? |
|-------|------|-------|---------|
| Shift-left | pre-commit + Gitleaks | Staged changes | Yes |
| Backstop | Gitleaks CI | Full repo + git history | No (on push/PR) |

Config: [`.gitleaks.toml`](.gitleaks.toml) — extends default rules; allowlists `src/webshop/config.py` for V04 training secrets only.

---

## Local setup

```bash
uv sync --dev
uv run pre-commit install

# One-off scan of entire repo (same config as CI)
uv run pre-commit run gitleaks --all-files
```

Pre-commit runs automatically on `git commit`.

### Bypass scenarios (why CI matters)

```bash
# Skips ALL hooks — pre-commit does not run
git commit --no-verify -m "oops"

# Skips only Gitleaks
SKIP=gitleaks git commit -m "oops"
```

Both can still be caught when you **push**, because CI scans full history with `fetch-depth: 0`.

---

## Scenario matrix

| Scenario | pre-commit | CI Gitleaks |
|----------|------------|-------------|
| Developer stages `.env` with AWS key | Blocks | Blocks on push |
| `git commit --no-verify` with secret | Skipped | Blocks on push |
| Secret committed months ago | N/A | Caught (full history) |
| V04 fake secrets in `config.py` | Pass (allowlisted) | Pass |
| New fake PAT / API key on demo branch | Blocks | Blocks on push |
| Edit only on GitHub web UI, no local hooks | N/A | Blocks on push |

**Interview line:** Pre-commit is fast feedback, not a guarantee. CI is the backstop.

---

## Demo branch playbook

**Branch:** `demo/leaked-aws-key` — **never merge to `main`**

Prove the pipeline catches a *new* leak (V04 on `main` is allowlisted so `main` stays green on Secrets).

### 1. Create the leak

Use **fake tokens Gitleaks will flag**. AWS documentation example keys (`AKIAIOSFODNN7EXAMPLE`) are in Gitleaks' default allowlist and will **not** trigger — use patterns like GitHub PAT or Stripe test keys instead.

```bash
git checkout -b demo/leaked-aws-key

mkdir -p demo
cat > demo/leaked.env << 'EOF'
# Intentional demo leak — fake credentials for pipeline test (not real)
GITHUB_TOKEN=
STRIPE_KEY=
EOF

git add demo/leaked.env
git commit -m "demo: intentional fake tokens for secrets pipeline"
```

Pre-commit should **block** this commit. To simulate bypass:

```bash
git commit --no-verify -m "demo: bypass pre-commit"
git push -u origin demo/leaked-aws-key
```

**Secrets** workflow should **fail** on GitHub.

### 2. Naive fix (not enough)

```bash
git rm demo/leaked.env
git commit -m "remove leaked file"
git push
```

The file is gone from HEAD, but the secret **still exists in git history**. Gitleaks with `fetch-depth: 0` may still report it.

### 3. Scrub git history

Use on the **demo branch only** — never force-push rewritten `main` without team agreement.

**Option A — git-filter-repo (recommended):**

```bash
pip install git-filter-repo

git filter-repo --path demo/leaked.env --invert-paths

# Force-push demo branch only
git push --force origin demo/leaked-aws-key
```

**Option B — BFG Repo-Cleaner:**

```bash
bfg --delete-files leaked.env
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push --force origin demo/leaked-aws-key
```

### 4. Rotate (production)

For a real incident:

1. **Revoke** the credential immediately (AWS IAM, GitHub PAT, etc.)
2. **Scrub** history or treat repo as compromised
3. **Audit** access logs for unauthorized use
4. **Notify** per incident response policy

For this demo, step 1 is N/A — keys are AWS doc examples.

### 5. Clean up

```bash
git checkout main
git branch -D demo/leaked-aws-key
# Delete remote demo branch when finished:
# git push origin --delete demo/leaked-aws-key
```

---

## Allowlist discipline

[`.gitleaks.toml`](.gitleaks.toml) allowlists **one path**:

```toml
paths = ['''src/webshop/config\.py''']
```

Production rules:

- Allowlist **paths** or **specific commits**, not broad regexes that hide real leaks
- Document every allowlist entry in this file or in PR description
- Review allowlists quarterly
- Prefer `gitleaks:allow` on a single known test line over blanket file ignores

---

## Tool comparison (this repo)

| Finding | Bandit | Semgrep `p/secrets` | Gitleaks |
|---------|--------|---------------------|----------|
| V04 hardcoded in Python | B105 (LOW) | Weak at ERROR gate | Allowlisted on `main` |
| Fake AWS key in `.env` | No (Bandit) | Maybe | **Yes** (unless AWS doc example — allowlisted by default) |
| Secret only in old commit | No | No | **Yes** |

See also: [NOTES.md](NOTES.md) (pattern vs taint), [SECURITY.md](SECURITY.md) (SAST findings), [SCA.md](SCA.md) (dependency CVEs).

---

## CI artifacts

On failure, check the **Secrets** workflow run in GitHub Actions. Gitleaks prints findings in the job log. Optional: add JSON report upload in a later iteration.

---

## Future work

- SARIF upload to GitHub Security tab
- TruffleHog for optional live verification of whether a secret is still active

Dependency CVE scanning is covered in **[SCA.md](SCA.md)** (Phase 4).
