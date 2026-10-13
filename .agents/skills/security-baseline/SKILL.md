---
name: security-baseline
description: >
  Apply security checks to every code change at all risk tiers. Covers secrets management,
  input validation, injection prevention, authentication and authorization, cryptography,
  error and log hygiene, and dependency security. Use for any code review, implementation,
  or verification task.
---

# Security Baseline

## Checklist

### Secrets
- [ ] No hardcoded credentials, tokens, API keys, or passwords in code
- [ ] No secrets in logs, test fixtures, prompts, comments, or error messages
- [ ] No secrets committed to version control (check `.env`, config, test data)
- [ ] Required secrets validated at startup — fail fast if missing
- [ ] Secrets loaded from environment variables or secret manager
- [ ] Different secrets per environment (dev/staging/prod)

### Input Validation
- [ ] All external inputs validated at system boundaries (user input, files, API responses, env vars, CLI args, headers, cookies, query params)
- [ ] Type, range, format, length, and encoding validated
- [ ] Allowlists over blocklists
- [ ] Backend re-validates even if frontend validates
- [ ] File uploads validated (type, size, content — not just extension)

### Injection Prevention
- [ ] Database: parameterized queries / prepared statements / ORM
- [ ] No SQL/command/template strings built from unsanitized input
- [ ] No dynamic code execution (eval, exec) unless sandboxed and justified
- [ ] Template engines: auto-escaping enabled
- [ ] OS commands avoided — if necessary, use library APIs, not shell execution

### Authentication & Authorization
- [ ] Both authentication (identity) and authorization (permission) present
- [ ] Resource-level authorization — users access only *their* resources
- [ ] Tenant/org isolation enforced where applicable
- [ ] Least-privilege — minimum necessary permissions
- [ ] Rate limiting on auth endpoints
- [ ] Session management secure (httpOnly, secure, sameSite cookies)

### Cryptography
- [ ] Established libraries only — never custom crypto
- [ ] No deprecated algorithms: MD5, SHA-1, DES, RC4, ECB mode
- [ ] Recommended: AES-256-GCM, RSA-2048+, SHA-256+, Ed25519
- [ ] Passwords: bcrypt, scrypt, or Argon2 (with salt, sufficient rounds)
- [ ] Secure random number generator (not Math.random / rand())
- [ ] TLS 1.2+ for all network communication

### Error & Log Hygiene
- [ ] User-facing errors generic — no stack traces, DB schemas, file paths, internal IPs
- [ ] Logs never contain: passwords, tokens, API keys, PII, credit cards, SSNs
- [ ] Error responses don't reveal whether a user/resource exists (prevent enumeration)
- [ ] Debug mode disabled in production

### Dependencies
- [ ] Dependencies minimized
- [ ] Versions pinned in production
- [ ] Security scanner run (npm audit, pip-audit, Snyk, Dependabot)
- [ ] No unmaintained or abandoned packages
- [ ] Unused dependencies removed

### Secure Defaults
- [ ] HTTPS enforced
- [ ] Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- [ ] CORS scoped to specific origins — not `*`
- [ ] Timeouts on all external calls

## Gotchas

- `.env` files committed to git are the #1 secret leak. Check `.gitignore` covers `.env*` before every commit.
- `os.environ.get("KEY", "")` silently returns empty string — app runs but fails mysteriously at runtime. Always fail fast on missing secrets.
- ORM `.raw()` / `.extra()` methods bypass parameterization. Treat them as hand-written SQL.
- `CORS: *` in dev often ships to prod. Set explicit origins from the start.
- `console.log(response)` in debugging can dump auth tokens. Structured logging with field allowlists prevents this.
- Framework auto-escaping is template-engine-specific — it won't protect `dangerouslySetInnerHTML`, `| safe`, or raw SQL.

## Patterns

### Secret loading
```python
# Fail fast — don't silently degrade
api_key = os.environ["API_KEY"]  # KeyError if missing
```

### Parameterized queries
```python
db.execute("SELECT * FROM users WHERE id = ?", [user_id])
# NOT: f"SELECT * FROM users WHERE id = {user_id}"
```

## Validation Loop

After implementing security-related code:
1. Search the diff for common leak patterns: `grep -E '(password|secret|token|api.key)' --include='*.py'`
2. Verify no new endpoints lack auth middleware
3. If issues found, fix and re-check until clean

## Anti-Patterns

- **"It's just an internal API"** — internal APIs get exposed. Validate anyway.
- **"The frontend validates"** — frontends can be bypassed. Always re-validate server-side.
- **"It's just dev"** — dev secrets leak. Treat seriously.
- **"We'll add security later"** — security debt compounds. Build it in.
