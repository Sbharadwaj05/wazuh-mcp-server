"""
Agent group management tools.

- wazuh_list_groups
- wazuh_get_group
- wazuh_group_agents
"""

from __future__ import annotations

from typing import Optional

import mcp.types as types
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.utils import extract_items, extract_total, format_json, paginated_result


def register_groups(mcp: FastMCP, client: WazuhClient) -> None:
    """Register agent-group management tools."""

    @mcp.tool(
        name="wazuh_list_groups",
        description=(
            "List all Wazuh agent groups. Groups are used to organize agents "
            "by function (e.g., 'web-servers', 'database', 'production'). "
            "Useful for scoping queries and active responses to specific agent sets."
        ),
    )
    async def wazuh_list_groups(
        search: Optional[str] = types.Field(
            default=None,
            description="Search groups by name",
        ),
        limit: int = types.Field(default=50, description="Maximum groups to return"),
        offset: int = types.Field(default=0, description="Pagination offset"),
    ) -> str:
        try:
            data = await client.list_groups(
                search=search, limit=min(limit, 500), offset=offset
            )
            items = extract_items(data)
            total = extract_total(data)
            result = paginated_result(
                items,
                total,
                offset,
                limit,
                summary=f"Found {total} agent group(s)"
                + (f" matching '{search}'" if search else ""),
            )
            return format_json(result)
        except Exception as e:
            return format_json({"error": str(e)})

    @mcp.tool(
        name="wazuh_get_group",
        description=(
            "Get detailed information about a specific agent group, "
            "including its configuration and member agents."
        ),
    )
    async def wazuh_get_group(
        group_id: str = types.Field(
            description="Group ID to inspect (e.g., 'default', 'web-servers')",
        ),
    ) -> str:
        try:
            data = await client.get_group(group_id)
            return format_json(data)
        except Exception as e:
            return format_json({"error": str(e)})

    @mcp.tool(
        name="wazuh_group_agents",
        description="List all agents belonging to a specific agent group.",
    )
    async def wazuh_group_agents(
        group_id: str = types.Field(
            description="Group ID to list agents for (e.g., 'web-servers')",
        ),
        limit: int = types.Field(default=50, description="Maximum agents to return"),
        offset: int = types.Field(default=0, description="Pagination offset"),
    ) -> str:
        try:
            data = await client.group_agents(
                group_id=group_id, limit=min(limit, 500), offset=offset
            )
            items = extract_items(data)
            total = extract_total(data)
            result = paginated_result(
                items,
                total,
                offset,
                limit,
                summary=f"Found {total} agent(s) in group '{group_id}'",
            )
            return format_json(result)
        except Exception as e:
            return format_json({"error": str(e)})
