"""Tool registration hub — imports and exposes all MCP tool modules."""

from wazuh_mcp.tools import agents, alerts, compliance, hunting, manager, response

__all__ = ["alerts", "agents", "compliance", "hunting", "manager", "response"]
