"""
Entry point for the Wazuh MCP server.

Creates a FastMCP instance, registers all tool modules, and starts the
stdio-based server that Claude Desktop / Cursor / Copilot connect to.
"""

from __future__ import annotations

import logging
import sys

from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.tools import agents, alerts, compliance, hunting, manager, response

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,  # MCP uses stdout for protocol messages
)
logger = logging.getLogger("wazuh-mcp")

# ---------------------------------------------------------------------------
# MCP Server setup
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="Wazuh MCP Server",
    instructions=(
        "You are an AI security analyst with full access to a Wazuh SIEM/XDR platform. "
        "You can query alerts, investigate threats, check compliance, manage agents, "
        "and trigger incident response actions (with confirmation). "
        "Always explain your findings in clear security terms and cite specific "
        "alert IDs, MITRE techniques, and agent names when presenting results."
    ),
)

# ---------------------------------------------------------------------------
# Client — created eagerly at startup (env vars loaded via dotenv)
# ---------------------------------------------------------------------------

_client = WazuhClient()

# Register all tools
alerts.register_alerts(mcp, _client)
agents.register_agents(mcp, _client)
compliance.register_compliance(mcp, _client)
hunting.register_hunting(mcp, _client)
manager.register_manager(mcp, _client)
response.register_response(mcp, _client)

logger.info("Registered %d tool modules", 6)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the MCP server (stdio transport)."""
    logger.info("Starting Wazuh MCP Server v0.1.0")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
