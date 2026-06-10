# Advanced Features

## Token-Efficient Output Modes

Combat context-window exhaustion with smart field selection:

| Mode | What it returns | Token savings |
|------|----------------|---------------|
| `triage` | Alert ID, level, rule, agent, timestamp, srcip | ~70% vs full |
| `detail` | All fields — full investigation context | 0% (baseline) |
| `compliance` | SCA check title, result, rationale, remediation | ~60% vs full |
| `hunting` | IOCs: IP, hash, file, command, process, domain | ~65% vs full |
| `fleet` | Agent name, status, OS, version, last seen | ~80% vs full |

Usage in tools:
```python
# The 'mode' parameter on wazuh_list_alerts auto-selects fields
wazuh_list_alerts(min_level=12, mode="triage")

# Post-hoc compactification
from wazuh_mcp.output import compact
compact_result = compact(raw_data)
```

## Multi-Manager Support

Connect to multiple Wazuh managers for fault tolerance:

```bash
# In .env
WAZUH_API_URLS=https://manager1:55000,https://manager2:55000,https://manager3:55000
```

The first manager is the primary. Additional managers are available for
round-robin failover in high-availability deployments.

## SSE Streaming

The server supports SSE transport for web-based AI clients:

```bash
# Start with SSE
python -c "from wazuh_mcp.server import main_sse; main_sse()"

# Or via Docker
docker run -p 8000:8000 -e WAZUH_API_URL=... wazuh-mcp-server
```

Endpoints:
- `http://localhost:8000/sse` — SSE event stream
- `http://localhost:8000/messages` — MCP message endpoint

## Compliance Frameworks

The `wazuh_rules_coverage_map` tool cross-references your Wazuh rules against:

- **MITRE ATT&CK** — Techniques and sub-techniques
- **NIST 800-53** — Security and privacy controls
- **PCI DSS** — Payment Card Industry requirements
- **GDPR** — General Data Protection Regulation articles
- **HIPAA** — Health Insurance Portability controls

## Security Analysis Pipeline

The recommended workflow for autonomous alert investigation:

```
1. wazuh_alert_summary     → What's happening right now?
2. wazuh_list_alerts       → Drill into specific alerts
3. wazuh_get_alert         → Get full alert context
4. wazuh_search_events     → Hunt for related IOCs
5. wazuh_query_fim         → Check for file tampering
6. wazuh_query_vulnerabilities → Are affected systems patched?
7. wazuh_incident_timeline → Reconstruct the attack chain
8. wazuh_rules_coverage_map → Check detection gaps
9. (optional) wazuh_run_active_response → Contain the threat
```

## Vulnerability Heatmap

`wazuh_vulnerability_heatmap` assigns a risk score per agent:

```
risk_score = (critical CVEs × 10) + (high CVEs × 5) + (medium CVEs × 2) + (low CVEs × 1)
```

Agents are ranked by risk score. Use this for patch prioritization.
