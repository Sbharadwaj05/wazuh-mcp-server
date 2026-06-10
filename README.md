# 🔐 Wazuh MCP Server

**AI-powered security operations for Wazuh SIEM/XDR — through natural language.**

> *"Show me all critical alerts in the last 6 hours, cross-reference with MITRE ATT&CK, and check if any affected hosts have unpatched CVEs."*

One prompt. Your AI assistant queries alerts, hunts threats, checks compliance, manages agents, and triggers incident response — all through the Wazuh REST API.

<p align="center">
  <em>🚧 Demo GIF coming soon — autonomous alert investigation in one prompt</em>
</p>

---

## What This Does

Turn your AI assistant (Claude Desktop, Cursor, Copilot) into a security analyst that can:

| Workflow | What you say | What happens |
|----------|-------------|--------------|
| **Alert Triage** | *"Summarize today's alerts by severity and MITRE technique"* | Queries Wazuh indexer, aggregates by level/rule/technique/IP |
| **Threat Hunting** | *"Search for IOC 10.0.0.50 across all events and FIM records"* | Searches raw events + file integrity monitoring |
| **Compliance Audit** | *"Show me all agents failing CIS benchmark checks"* | Pulls SCA results per agent, per policy |
| **Fleet Health** | *"List disconnected agents and their last seen time"* | Agent summary + detailed per-agent view |
| **Vulnerability Mgmt** | *"Any critical CVEs on the production group?"* | Vulnerability-detector inventory by severity/CVE |
| **MITRE Coverage** | *"Which of my rules cover T1059 (Command & Scripting Interpreter)?"* | Searches rules by MITRE technique |
| **Incident Response** ⚠️ | *"Block IP 203.0.113.55 on all web servers"* | Triggers active-response (with safety confirmation) |

---

## Installation

### Prerequisites

- Python 3.10+
- A Wazuh 4.7+ manager (or use the included Docker stack)

### Quick Start (with Docker)

```bash
git clone https://github.com/Sbharadwaj05/wazuh-mcp-server.git
cd wazuh-mcp-server

# One command: spins up Wazuh manager + indexer + dashboard
chmod +x scripts/setup.sh
./scripts/setup.sh

# Or manually:
docker compose up -d
pip install -e ".[dev]"
```

### Connect to an Existing Wazuh Instance

```bash
pip install -e .

# Create your .env
cp .env.example .env
# Edit .env with your Wazuh manager URL and credentials

# Test it
python -m wazuh_mcp.server
```

### Claude Desktop / Cursor Configuration

Add this to your MCP config (`claude_desktop_config.json` or Cursor's MCP settings):

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

## Tools Reference

### 🔔 Alerts & Triage
| Tool | Description |
|------|-------------|
| `wazuh_list_alerts` | Query alerts by severity, agent, rule ID, MITRE technique, free-text search |
| `wazuh_get_alert` | Fetch full alert detail by ID |
| `wazuh_alert_summary` | Aggregated view: severity distribution, top rules, top IPs, MITRE coverage |

### 🔍 Threat Hunting
| Tool | Description |
|------|-------------|
| `wazuh_search_events` | Search raw events for IOCs (IPs, hashes, commands, process names) |
| `wazuh_query_fim` | File Integrity Monitoring — what files changed, when, by whom |
| `wazuh_query_vulnerabilities` | CVE inventory per agent, filterable by severity |
| `wazuh_search_mitre` | Search MITRE ATT&CK techniques and their Wazuh rule mappings |

### 📋 Compliance
| Tool | Description |
|------|-------------|
| `wazuh_sca_status` | SCA policy compliance scores per agent (CIS, PCI DSS, NIST, GDPR) |
| `wazuh_sca_checks` | Per-check pass/fail detail, filterable by policy and result |
| `wazuh_compliance_report` | Fleet-wide compliance report across all agents |

### 🖥️ Agents & Fleet
| Tool | Description |
|------|-------------|
| `wazuh_list_agents` | List agents with status, OS, version, search, pagination |
| `wazuh_get_agent` | Deep-dive on a single agent: config, modules, groups |
| `wazuh_agent_health` | Fleet health overview: status counts, OS breakdown, stale agents |

### ⚙️ Manager & Rules
| Tool | Description |
|------|-------------|
| `wazuh_manager_stats` | EPS, queue sizes, daemon health |
| `wazuh_cluster_status` | Cluster node list and sync status |
| `wazuh_rules_info` | Search rules by level, compliance framework (PCI, GDPR, HIPAA, NIST), MITRE |

### ⚠️ Incident Response
| Tool | Description |
|------|-------------|
| `wazuh_run_active_response` | Trigger active response (firewall-drop, host-deny, restart-wazuh) |
| `wazuh_agent_command` | Execute arbitrary command on a remote agent |

> **🔒 SAFETY**: `wazuh_run_active_response` and `wazuh_agent_command` require explicit confirmation before execution. By default they return a "here's what would happen — are you sure?" prompt with a one-time confirmation token. A misconfigured LLM cannot silently block IPs or quarantine hosts.

---

## Project Structure

```
Wazuh-MCP/
├── src/wazuh_mcp/
│   ├── server.py           # Entry point — FastMCP instance + tool registration
│   ├── client.py           # Async Wazuh REST API client (JWT auth, pagination)
│   ├── utils.py            # JSON formatters, pagination helpers
│   └── tools/
│       ├── alerts.py       # wazuh_list_alerts, wazuh_get_alert, wazuh_alert_summary
│       ├── hunting.py      # wazuh_search_events, wazuh_query_fim, vulnerabilities, MITRE
│       ├── compliance.py   # wazuh_sca_status, wazuh_sca_checks, wazuh_compliance_report
│       ├── agents.py       # wazuh_list_agents, wazuh_get_agent, wazuh_agent_health
│       ├── manager.py      # wazuh_manager_stats, wazuh_cluster_status, wazuh_rules_info
│       └── response.py     # wazuh_run_active_response, wazuh_agent_command (with safety)
├── tests/                  # pytest-asyncio tests for each tool domain
├── scripts/setup.sh        # One-command Wazuh + MCP dev environment
├── docker-compose.yml      # Wazuh 4.9 single-node stack
├── pyproject.toml
└── .env.example
```

---

## Security Considerations

1. **TLS**: Always use `WAZUH_INSECURE=false` in production. The Docker dev stack uses self-signed certs with `WAZUH_INSECURE=true` for local testing only.
2. **Credentials**: Store Wazuh credentials in `.env` (gitignored). Never commit them.
3. **Confirmation Gate**: Destruction tools (`wazuh_run_active_response`, `wazuh_agent_command`) require a two-step confirmation flow with expiring tokens. Review the [response.py](src/wazuh_mcp/tools/response.py) implementation for details.
4. **Least Privilege**: Create a dedicated Wazuh API user with only the permissions your AI workflows need. Avoid using the default `admin` account in production.

---

## Roadmap

- [ ] Streaming alert feed (SSE transport for real-time SOC workflows)
- [ ] Graph-based attack path visualization via MCP resources
- [ ] Integration with OT Sentinel ruleset for ICS/SCADA detection
- [ ] Natural language → Wazuh rule generator
- [ ] Automated post-incident timeline reconstruction
- [ ] Multi-manager / multi-cluster support

---

## License

MIT © [Sbharadwaj05](https://github.com/Sbharadwaj05)
