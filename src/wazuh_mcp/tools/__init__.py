"""Tool registration hub — 9 domains, 28 MCP tools."""

from wazuh_mcp.tools import (
    agents,
    alerts,
    analysis,
    compliance,
    groups,
    hunting,
    lists,
    manager,
    response,
)

__all__ = [
    "alerts",
    "agents",
    "compliance",
    "hunting",
    "manager",
    "response",
    "groups",
    "lists",
    "analysis",
]
