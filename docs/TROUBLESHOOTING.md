# Troubleshooting

## Common Issues

### "Wazuh API connection refused"

```
WazuhAPIError [connection]: HTTPConnectionPool(host='localhost', port=55000)
```

**Fix:**
1. Check if Wazuh manager is running: `docker compose ps wazuh.manager`
2. Verify the API port is exposed: `curl -k https://localhost:55000/`
3. Ensure `.env` has the correct `WAZUH_API_URL`
4. If using Docker, use the service name: `WAZUH_API_URL=https://wazuh.manager:55000`

### "Invalid JSON response body"

**Fix:**
- This usually means the Wazuh API returned HTML (e.g., a 502 error page)
- Check Wazuh manager logs: `docker compose logs wazuh.manager`
- Verify the indexer is healthy: `curl -k https://localhost:9200/`

### "Rate limit exceeded"

```json
{"error": "Rate limit exceeded for wazuh_list_alerts. Retry in 12s."}
```

**Fix:**
- Increase limits: `WAZUH_RATE_LIMIT_TOKENS=60` and `WAZUH_RATE_LIMIT_PERIOD=30`
- Or disable: set both to very high values
- The AI assistant should naturally batch queries — if it's calling too fast, adjust its system prompt

### "Confirmation token expired"

```
Confirmation token has expired (5-minute window)
```

**Fix:**
- Tokens expire after 5 minutes for security
- Simply call the tool again without `confirm=True` to get a fresh token
- This is by design — prevents replay attacks

### MCP server won't start (import error)

```
ModuleNotFoundError: No module named 'wazuh_mcp'
```

**Fix:**
```bash
pip install -e ".[dev]"
```

### Tests fail

```
FAILED tests/test_alerts.py::TestAlertTools::test_get_alert_not_found_raises
```

**Fix:**
```bash
pip install -e ".[dev]"
python -m pytest tests/ -v --tb=long
```

### Claude Desktop doesn't see the tools

**Fix:**
1. Check the MCP config path is correct
2. Ensure `cwd` points to the `src/` directory
3. Verify Python path: use absolute path to python executable
4. Check Claude Desktop logs: `~/Library/Logs/Claude/mcp*.log` (macOS) or `%APPDATA%\Claude\logs` (Windows)

### Wazuh Dashboard shows no alerts

The dev Docker stack doesn't include agents. You won't see alerts until you:
1. Install Wazuh agents on some hosts, OR
2. Use the manager's built-in SCA results (agent `000`)

---

## Debug Mode

Enable verbose logging:

```bash
export WAZUH_MCP_LOG_LEVEL=DEBUG
python -m wazuh_mcp.server
```

## Checking the Audit Log

```bash
# View last 20 entries
tail -20 ~/.wazuh-mcp/audit.jsonl | python -m json.tool

# Count actions by tool
cat ~/.wazuh-mcp/audit.jsonl | python -c "
import sys, json
from collections import Counter
c = Counter()
for line in sys.stdin:
    try: c[json.loads(line)['tool']] += 1
    except: pass
print(dict(c))
"
```
