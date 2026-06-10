# Development Guide

## Project Architecture

```
src/wazuh_mcp/
├── server.py           # FastMCP instance, tool registration, entry points
├── client.py           # Async Wazuh REST API client (JWT, pagination)
├── audit.py            # Immutable audit logging (append-only JSONL)
├── sanitizer.py        # Output sanitization (credential redaction)
├── rate_limiter.py     # Token-bucket per-tool rate limiting
├── validators.py       # Input validation (regex, shell meta blocking)
├── output.py           # Token-efficient output modes + smart field selection
├── utils.py            # JSON formatters, pagination helpers
└── tools/
    ├── alerts.py       # Alert triage (3 tools)
    ├── hunting.py      # Threat hunting (4 tools)
    ├── compliance.py   # SCA compliance (3 tools)
    ├── agents.py       # Agent management (3 tools)
    ├── groups.py       # Agent groups (3 tools)
    ├── lists.py        # CDB lists (2 tools)
    ├── manager.py      # Manager stats, logs, cluster (5 tools)
    ├── response.py     # Active response w/ safety gate (2 tools)
    └── analysis.py     # Coverage maps, heatmaps, timelines (3 tools)
```

## Adding a New Tool

1. **Add client method** in `client.py`:
```python
async def my_new_endpoint(self, param: str) -> Dict[str, Any]:
    return await self._get(f"/my/endpoint/{param}")
```

2. **Create/update tool module** in `tools/`:
```python
from mcp.server.fastmcp import FastMCP

def register_myfeature(mcp: FastMCP, client: WazuhClient) -> None:
    @mcp.tool(name="wazuh_my_tool", description="...")
    async def wazuh_my_tool(param: str = types.Field(...)) -> str:
        try:
            data = await client.my_new_endpoint(param)
            return format_json(data)
        except Exception as e:
            return format_json({"error": str(e)})
```

3. **Register in server.py**:
```python
from wazuh_mcp.tools import myfeature
myfeature.register_myfeature(mcp, _client)
```

4. **Add tests** in `tests/`.

## Running Locally

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run the MCP server (stdio mode — for Claude Desktop / Cursor)
python -m wazuh_mcp.server

# Run with SSE transport (for web clients)
python -c "from wazuh_mcp.server import main_sse; main_sse()"

# Run tests
python -m pytest tests/ -v

# Run single test file
python -m pytest tests/test_alerts.py -v
```

## Docker Development

```bash
# Build and run the full stack
docker compose up -d

# Rebuild just the MCP server
docker compose build wazuh-mcp
docker compose up -d wazuh-mcp

# View MCP server logs
docker compose logs -f wazuh-mcp

# View Wazuh manager logs
docker compose logs -f wazuh.manager
```

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_API_URL` | `https://localhost:55000` | Wazuh manager API URL |
| `WAZUH_API_URLS` | — | Comma-separated URLs for multi-manager |
| `WAZUH_USERNAME` | `admin` | API username |
| `WAZUH_PASSWORD` | — | API password |
| `WAZUH_INSECURE` | `false` | Skip TLS verification |
| `WAZUH_TIMEOUT` | `30` | API timeout (seconds) |
| `WAZUH_RATE_LIMIT_TOKENS` | `30` | Max burst requests per tool |
| `WAZUH_RATE_LIMIT_PERIOD` | `60` | Refill window (seconds) |
| `WAZUH_AUDIT_LOG` | `~/.wazuh-mcp/audit.jsonl` | Audit log path |
| `WAZUH_MCP_HOST` | `127.0.0.1` | SSE bind address |
| `WAZUH_MCP_PORT` | `8000` | SSE port |

## Release Process

1. Update version in `pyproject.toml` and `src/wazuh_mcp/__init__.py`
2. Update `CHANGELOG.md`
3. Create a git tag: `git tag v0.2.0 && git push --tags`
4. GitHub Actions builds and publishes to PyPI
