# Changelog

All notable changes to the Wazuh MCP Server project.

## [0.2.0] — Unreleased

### Security & Production Hardening 🛡️
- **Audit logging**: Immutable, append-only JSONL audit trail for all destructive actions
- **Output sanitization**: Automatic redaction of credentials, API keys, JWT tokens, passwords from LLM-bound data
- **API rate limiting**: Per-tool token-bucket rate limiter with stricter limits on destructive tools
- **Input validation**: Shell metacharacter blocking, regex validation for agent IDs, IPs, CVEs, MITRE IDs
- **Dependency scanning**: GitHub Actions with pip-audit + CodeQL + Dependabot
- **Non-root Docker**: Production container runs as unprivileged `wazuhmcp` user

### Developer Experience 🧠
- **Comprehensive docs**: SECURITY.md, DEVELOPMENT.md, ADVANCED_FEATURES.md, TROUBLESHOOTING.md
- **GitHub CI/CD**: Multi-Python test matrix, ruff linting, automated releases to PyPI
- **Docker production build**: Multi-stage Dockerfile with health checks
- **docker-compose**: Full Wazuh stack + MCP server in one `docker compose up`
- **Release automation**: Tag-triggered GitHub Releases + PyPI publishing

### AI/LLM Operational Efficiency 🤖
- **Token-efficient output modes**: `triage`, `detail`, `compliance`, `hunting`, `fleet` with smart field selection
- **Compact mode**: Strips verbose metadata, truncates long strings, limits array sizes
- **SSE transport**: Streaming HTTP endpoint for web-based AI clients (`main_sse()`)

### Feature Completeness 📊
- **Agent groups**: `wazuh_list_groups`, `wazuh_get_group`, `wazuh_group_agents`
- **CDB lists**: `wazuh_list_cdb_lists`, `wazuh_get_cdb_list`
- **Per-node cluster stats**: `wazuh_cluster_node_stats`
- **Manager logs**: `wazuh_manager_logs` with category and search filters
- **Rules coverage map**: `wazuh_rules_coverage_map` — MITRE, NIST 800-53, PCI DSS, GDPR, HIPAA
- **Vulnerability heatmap**: `wazuh_vulnerability_heatmap` — risk-scored per-agent CVE inventory
- **Incident timeline**: `wazuh_incident_timeline` — auto-generated event chronology
- **Multi-manager support**: Round-robin client pool via `WAZUH_API_URLS`

## [0.1.0] — 2024-06-10

### Initial Release
- 16 MCP tools across 6 domains (alerts, hunting, compliance, agents, manager, response)
- Async Wazuh REST API client with JWT auth and auto-refresh
- Two-step confirmation gate for destructive tools (active response, agent commands)
- Docker Compose dev stack with Wazuh 4.9 single-node
- 12 pytest-asyncio tests
- Claude Desktop / Cursor MCP configuration
