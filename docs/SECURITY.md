# Security Policy

## Defense-in-Depth Architecture

The Wazuh MCP Server implements multiple layers of security controls:

### 🛡️ Layer 1: Input Validation
All tool parameters are validated before reaching the Wazuh API:
- **Shell metacharacter blocking** — Rejects `;`, `&`, `|`, `` ` ``, `$`, `(`, `)`, etc.
- **Type validation** — Agent IDs (`^\d{3}$`), IPs, CVE IDs, MITRE technique IDs, rule IDs
- **Length limits** — All free-text fields capped at 500 characters
- **Null byte detection** — Blocks byte injection attacks

See: `src/wazuh_mcp/validators.py`

### 🔒 Layer 2: API Rate Limiting
Token-bucket rate limiter per tool:
- **Default**: 30 requests / 60 seconds per tool
- **Destructive tools**: 5 requests / 120 seconds (stricter)
- Configurable via `WAZUH_RATE_LIMIT_TOKENS` and `WAZUH_RATE_LIMIT_PERIOD`

See: `src/wazuh_mcp/rate_limiter.py`

### 🔍 Layer 3: Output Sanitization
All Wazuh API responses are scanned before reaching the LLM:
- **Credential redaction** — AWS keys, GCP keys, JWT tokens, API keys, passwords
- **Sensitive field blocking** — `password`, `secret`, `token`, `private_key`, etc.
- **SSH key detection** — PEM headers are redacted
- **Bearer token stripping** — Authorization headers removed

See: `src/wazuh_mcp/sanitizer.py`

### 📝 Layer 4: Audit Logging
All destructive actions are recorded in an append-only audit log:
- **JSON Lines format** — Machine-parseable, one entry per line
- **Immutable** — Append-only, never truncated
- **Thread-safe** — Mutex-protected writes
- **Default location**: `~/.wazuh-mcp/audit.jsonl`

See: `src/wazuh_mcp/audit.py`

### ⚠️ Layer 5: Confirmation Gate
Destructive tools require explicit two-step confirmation:
1. First call returns a "Here's what will happen — are you sure?" prompt
2. Must call again with `confirm=True` + one-time token (5-minute expiry)

**A misconfigured LLM cannot silently block IPs or quarantine hosts.**

See: `src/wazuh_mcp/tools/response.py`

### 🔐 Layer 6: Transport Security
- **TLS everywhere** — `WAZUH_INSECURE=false` in production
- **Non-root user** — Docker container runs as `wazuhmcp`
- **No credential storage** — Credentials via env vars only (.env is gitignored)
- **JWT authentication** — Automatic token refresh, never stored to disk

---

## Reporting a Vulnerability

**Do not open a public issue.** Email the maintainer directly.

We follow a 90-day responsible disclosure policy. Critical vulnerabilities will be patched within 48 hours of confirmation.

---

## Dependency Scanning

- **Dependabot** — Weekly dependency updates (pip + Docker)
- **pip-audit** — Every push + weekly schedule
- **CodeQL** — Static analysis on every push

See: `.github/workflows/security-scan.yml`

---

## Production Deployment Checklist

- [ ] Change default passwords (`SecretPassword` in docker-compose)
- [ ] Set `WAZUH_INSECURE=false`
- [ ] Create dedicated Wazuh API user with least-privilege roles
- [ ] Enable TLS with valid certificates (not self-signed)
- [ ] Configure audit log rotation (external logrotate)
- [ ] Set `WAZUH_RATE_LIMIT_TOKENS` appropriate for your SOC workflow
- [ ] Review and approve all active-response commands in ossec.conf
- [ ] Run dependency audit: `pip-audit`
- [ ] Deploy behind a reverse proxy with request logging
