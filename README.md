# 🔐 Wazuh MCP Server

**28 MCP tools. 9 domains. AI-powered security operations for Wazuh SIEM/XDR.**

<p align="center">
  <a href="https://github.com/Sbharadwaj05/wazuh-mcp-server/actions/workflows/ci.yml"><img src="https://github.com/Sbharadwaj05/wazuh-mcp-server/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Sbharadwaj05/wazuh-mcp-server/actions/workflows/security-scan.yml"><img src="https://github.com/Sbharadwaj05/wazuh-mcp-server/actions/workflows/security-scan.yml/badge.svg" alt="Security Scan"></a>
  <a href="https://github.com/Sbharadwaj05/wazuh-mcp-server/actions/workflows/codeql.yml"><img src="https://github.com/Sbharadwaj05/wazuh-mcp-server/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://pypi.org/project/wazuh-mcp-server/"><img src="https://img.shields.io/pypi/v/wazuh-mcp-server" alt="PyPI"></a>
  <a href="https://github.com/Sbharadwaj05/wazuh-mcp-server/blob/master/LICENSE"><img src="https://img.shields.io/github/license/Sbharadwaj05/wazuh-mcp-server" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue" alt="Python">
</p>

> *"Show me all critical alerts in the last 6 hours, cross-reference with MITRE ATT&CK, and check if any affected hosts have unpatched CVEs."*

One prompt. Your AI assistant queries alerts, hunts threats, checks compliance, manages agents, and triggers incident response — all through the Wazuh REST API.

<p align="center">
  <em>🚧 Demo GIF coming soon — autonomous alert investigation in one prompt</em>
</p>

---

## 🛡️ Security Features (Defense in Depth)

- [x] **Input validation** — Shell metacharacter blocking, regex for agent IDs, IPs, CVEs, MITRE IDs
- [x] **Rate limiting** — Token-bucket: 30/60s for read tools, 5/120s for destructive
- [x] **Output sanitization** — Redacts AWS keys, JWT tokens, SSH keys, API keys, passwords
- [x] **Audit logging** — Append-only JSONL trail for all destructive actions
- [x] **Confirmation gate** — Two-step `confirm=True` + expiring token for active response
- [x] **RBAC** — 4 built-in roles: `viewer`, `analyst`, `admin`, `soc`
- [x] **Dependabot + pip-audit + CodeQL** — Automated dependency scanning on every push
- [x] **Non-root Docker** — Production container runs as unprivileged `wazuhmcp` user
- [x] **TLS everywhere** — `WAZUH_INSECURE=false` in production

---

## 📊 What This Does

| Workflow | What you say | What happens |
|----------|-------------|--------------|
| **Alert Triage** | *"Summarize today's alerts by severity and MITRE technique"* | Queries Wazuh indexer, aggregates by level/rule/technique/IP |
| **Threat Hunting** | *"Search for IOC 10.0.0.50 across all events and FIM records"* | Searches raw events + file integrity monitoring |
| **Compliance Audit** | *"Show me all agents failing CIS benchmark checks"* | Pulls SCA results per agent, per policy |
| **Rules Coverage** | *"What's my NIST 800-53 detection coverage?"* | Cross-references rules against MITRE/NIST/PCI/GDPR/HIPAA |
| **Vulnerability Mgmt** | *"Which systems have critical unpatched CVEs?"* | Risk-scored vulnerability heatmap across all agents |
| **Incident Timeline** | *"Reconstruct what happened around alert #45821"* | Auto-generated chronological event timeline |
| **Incident Response** ⚠️ | *"Block IP 203.0.113.55 on all web servers"* | Triggers active-response (with safety confirmation) |

---

## 📦 Installation

### pip (PyPI)

```bash
pip install wazuh-mcp-server
```

### From source

```bash
git clone https://github.com/Sbharadwaj05/wazuh-mcp-server.git
cd wazuh-mcp-server
pip install -e ".[dev]"
```

### Docker (full stack in one command)

```bash
git clone https://github.com/Sbharadwaj05/wazuh-mcp-server.git
cd wazuh-mcp-server

# Spins up Wazuh 4.9 + MCP server + Prometheus metrics
docker compose up -d

# View API docs at http://localhost:8000/docs
# Prometheus metrics at http://localhost:9090/metrics
# Wazuh dashboard at https://localhost:443
```

### Claude Desktop / Cursor

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["-m", "wazuh_mcp.server"],
      "cwd": "/path/to/wazuh-mcp-server/src",
      "env": {
        "WAZUH_API_URL": "https://your-wazuh-manager:55000",
        "WAZUH_USERNAME": "admin",
        "WAZUH_PASSWORD": "your-password",
        "WAZUH_INSECURE": "false"
      }
    }
  }
}
```

---

## 🔧 Tools Reference (28 tools, 9 domains)

### 🔔 Alerts & Triage
| Tool | Description |
|------|-------------|
| `wazuh_list_alerts` | Query alerts by severity, agent, rule ID, MITRE technique, free-text |
| `wazuh_get_alert` | Fetch full alert detail by ID |
| `wazuh_alert_summary` | Aggregated: severity distribution, top rules, top IPs, MITRE coverage |

### 🔍 Threat Hunting
| Tool | Description |
|------|-------------|
| `wazuh_search_events` | Search raw events for IOCs |
| `wazuh_query_fim` | File Integrity Monitoring records |
| `wazuh_query_vulnerabilities` | CVE inventory per agent |
| `wazuh_search_mitre` | Search MITRE ATT&CK techniques |

### 📋 Compliance
| Tool | Description |
|------|-------------|
| `wazuh_sca_status` | SCA policy compliance scores |
| `wazuh_sca_checks` | Per-check pass/fail detail |
| `wazuh_compliance_report` | Fleet-wide compliance report |

### 🖥️ Agents & Groups
| Tool | Description |
|------|-------------|
| `wazuh_list_agents` | List agents with filters |
| `wazuh_get_agent` | Deep-dive on a single agent |
| `wazuh_agent_health` | Fleet health overview |
| `wazuh_list_groups` | List agent groups |
| `wazuh_get_group` | Group details and agents |
| `wazuh_group_agents` | Agents in a specific group |

### 📚 CDB Lists
| Tool | Description |
|------|-------------|
| `wazuh_list_cdb_lists` | List CDB threat-intel lists |
| `wazuh_get_cdb_list` | Read CDB list contents |

### ⚙️ Manager & Cluster
| Tool | Description |
|------|-------------|
| `wazuh_manager_stats` | EPS, queue sizes, daemon health |
| `wazuh_manager_logs` | Manager log retrieval |
| `wazuh_cluster_status` | Cluster node list and sync |
| `wazuh_cluster_node_stats` | Per-node statistics |
| `wazuh_rules_info` | Search rules by framework/MITRE |

### 📊 Security Analysis
| Tool | Description |
|------|-------------|
| `wazuh_rules_coverage_map` | MITRE/NIST/PCI/GDPR/HIPAA coverage matrix |
| `wazuh_vulnerability_heatmap` | Risk-scored CVE heatmap |
| `wazuh_incident_timeline` | Auto-generated attack timeline |

### ⚠️ Incident Response
| Tool | Description |
|------|-------------|
| `wazuh_run_active_response` | Trigger firewall-drop, host-deny, restart |
| `wazuh_agent_command` | Execute command on remote agent |

> **🔒 SAFETY**: Destructive tools require two-step `confirm=True` + expiring token. A misconfigured LLM cannot silently block IPs or quarantine hosts.

---

## 🖥️ Observability

### Prometheus Metrics (`:9090/metrics`)

| Metric | Type | Description |
|--------|------|-------------|
| `wazuh_mcp_tool_calls_total` | Counter | Tool invocations by name + status |
| `wazuh_mcp_tool_duration_seconds` | Histogram | P50/P95/P99 latency per tool |
| `wazuh_mcp_rate_limits_total` | Counter | Rate-limit rejections per tool |
| `wazuh_mcp_api_up` | Gauge | Wazuh API connectivity (1=up) |
| `wazuh_mcp_audit_entries_total` | Counter | Audit log entries written |
| `wazuh_mcp_active_requests` | Gauge | In-flight tool calls |
| `wazuh_mcp_tool_errors_total` | Counter | Errors by tool + error type |

### OpenAPI / Swagger (`:8000/docs`)

Interactive API documentation at `/docs` with full schema for all 28 tools.
Raw OpenAPI 3.0 spec at `/openapi.json`.

### Audit Log (`~/.wazuh-mcp/audit.jsonl`)

Append-only JSON Lines format. One entry per destructive action. Never truncated.

---

## 🔐 RBAC

Four built-in roles with hierarchical access:

| Role | Access Level | Tools |
|------|-------------|-------|
| `viewer` | Read-only | Alerts, agents, compliance, rules |
| `analyst` | + Investigation | Hunting, MITRE, CDB lists, analysis |
| `admin` | + Administration | Manager stats, logs, cluster management |
| `soc` | + Response ⚠️ | Active response, agent commands |

```bash
# Restrict to analyst role
export WAZUH_RBAC_ROLE=analyst

# Or use custom policy file
export WAZUH_RBAC_POLICY=/etc/wazuh-mcp/rbac.json
```

---

## 📁 Project Structure

```
Wazuh-MCP/
├── src/wazuh_mcp/
│   ├── server.py           # FastMCP entry point (stdio + SSE)
│   ├── client.py           # Async Wazuh REST API (JWT, pagination)
│   ├── rbac.py             # Role-Based Access Control (4 roles)
│   ├── audit.py            # Immutable audit logging (JSONL)
│   ├── sanitizer.py        # Output sanitization (credential redaction)
│   ├── rate_limiter.py     # Token-bucket per-tool rate limiting
│   ├── validators.py       # Input validation (regex, shell meta)
│   ├── metrics.py          # Prometheus metrics exporter
│   ├── openapi.py          # OpenAPI 3.0 + Swagger UI generator
│   ├── output.py           # Token-efficient field selection
│   ├── utils.py            # JSON formatters, pagination helpers
│   └── tools/              # 9 tool modules, 28 tools
├── tests/                  # pytest-asyncio test suite
├── docs/                   # SECURITY, DEVELOPMENT, ADVANCED_FEATURES, TROUBLESHOOTING
├── scripts/setup.sh        # One-command dev environment
├── docker-compose.yml      # Wazuh 4.9 + MCP server + Prometheus
├── Dockerfile              # Multi-stage production build
├── openapi.json            # Generated OpenAPI 3.0 specification
├── .github/workflows/      # CI (test matrix), Release, Security Scan
├── CHANGELOG.md
└── README.md
```

---

## 🚀 Quick Start

```bash
# 1. Clone and start everything
git clone https://github.com/Sbharadwaj05/wazuh-mcp-server.git
cd wazuh-mcp-server
docker compose up -d

# 2. Wait ~2 minutes for Wazuh to initialize

# 3. Explore
#    - Swagger UI:    http://localhost:8000/docs
#    - Prometheus:    http://localhost:9090/metrics
#    - Wazuh Dashboard: https://localhost:443  (admin / SecretPassword)
#    - MCP Server:    http://localhost:8000/sse
#    - OpenAPI JSON:  http://localhost:8000/openapi.json

# 4. Connect Claude Desktop using claude_desktop_config.json.example
```

---

## 🔒 Security Policy

See [SECURITY.md](docs/SECURITY.md) for full defense-in-depth documentation and production deployment checklist.

---

## 📄 License

MIT © [Sbharadwaj05](https://github.com/Sbharadwaj05)
