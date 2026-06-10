"""
Agent & fleet management tools.

- wazuh_list_agents
- wazuh_get_agent
- wazuh_agent_health
"""

from __future__ import annotations

from collections import Counter
from typing import Optional

import mcp.types as types
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.utils import extract_items, extract_total, format_json, paginated_result


def register_agents(mcp: FastMCP, client: WazuhClient) -> None:
    """Register all agent-management tools on the MCP server."""

    @mcp.tool(
        name="wazuh_list_agents",
        description=(
            "List all Wazuh agents with their status, OS, version, and last connection. "
            "Filter by status ('active', 'disconnected', 'never_connected'), "
            "search by name or IP, and control pagination."
        ),
    )
    async def wazuh_list_agents(
        status: Optional[str] = types.Field(
            default=None,
            description="Filter by connection status: 'active', 'disconnected', 'never_connected', 'pending'",
        ),
        older_than: Optional[str] = types.Field(
            default=None,
            description="Show agents not seen in this duration (e.g., '1d', '4h', '30m')",
        ),
        search: Optional[str] = types.Field(
            default=None,
            description="Search by agent name, IP, or ID",
        ),
        sort: Optional[str] = types.Field(
            default=None,
            description="Sort field, prefix with '-' for descending (e.g., '-last_keepalive')",
        ),
        limit: int = types.Field(
            default=50,
            description="Maximum agents to return (1-500)",
        ),
        offset: int = types.Field(
            default=0,
            description="Pagination offset",
        ),
    ) -> str:
        try:
            data = await client.list_agents(
                status=status,
                older_than=older_than,
                search=search,
                sort=sort,
                limit=min(limit, 500),
                offset=offset,
            )
            items = extract_items(data)
            total = extract_total(data)

            summary = f"Found {total} agent(s)"
            if status:
                summary += f" with status '{status}'"
            if search:
                summary += f" matching '{search}'"

            result = paginated_result(items, total, offset, limit, summary=summary)
            return format_json(result)
        except Exception as e:
            return format_json({"error": str(e)})

    @mcp.tool(
        name="wazuh_get_agent",
        description=(
            "Get detailed information about a specific agent: configuration, "
            "enabled modules, OS details, group membership, and connection history."
        ),
    )
    async def wazuh_get_agent(
        agent_id: str = types.Field(
            description="The agent ID to inspect (e.g., '001')",
        ),
    ) -> str:
        try:
            agent = await client.get_agent(agent_id)
            return format_json(agent)
        except Exception as e:
            return format_json({"error": str(e)})

    @mcp.tool(
        name="wazuh_agent_health",
        description=(
            "Get a fleet-wide health overview: counts by connection status, "
            "agents by OS/platform, version distribution, and stale agents. "
            "Use this for daily ops check or before an investigation."
        ),
    )
    async def wazuh_agent_health(
        stale_threshold_hours: int = types.Field(
            default=24,
            description="Hours after which an agent is considered stale (default: 24)",
        ),
    ) -> str:
        try:
            # Fetch agent summary (counts by status)
            summary_data = await client.agent_summary()
            status_counts = summary_data if isinstance(summary_data, dict) else {}

            # Fetch full agent list for detailed breakdown
            agents_data = await client.list_agents(limit=500)
            agent_items = extract_items(agents_data)

            os_counter: Counter = Counter()
            version_counter: Counter = Counter()
            stale_agents: list[dict] = []
            disconnected_agents: list[dict] = []

            for agent in agent_items:
                os_name = agent.get("os", {}).get("name", "unknown")
                os_counter[os_name] += 1

                version = agent.get("version", "unknown")
                version_counter[version] += 1

                agent_status = agent.get("status", "unknown")
                if agent_status == "disconnected":
                    disconnected_agents.append(
                        {
                            "id": agent.get("id"),
                            "name": agent.get("name"),
                            "ip": agent.get("ip"),
                            "last_keepalive": agent.get("last_keepalive"),
                            "version": version,
                        }
                    )

            health_report = {
                "connection_summary": status_counts,
                "total_agents": len(agent_items),
                "disconnected_agents": disconnected_agents,
                "os_breakdown": dict(os_counter.most_common()),
                "version_breakdown": dict(version_counter.most_common()),
                "stale_threshold_hours": stale_threshold_hours,
            }
            return format_json(health_report)
        except Exception as e:
            return format_json({"error": str(e)})
