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
from wazuh_mcp.output import compact
from wazuh_mcp.safe_tool import safe_tool
from wazuh_mcp.utils import extract_items, extract_total, format_json, paginated_result
from wazuh_mcp.validators import (
    validate_limit,
    validate_offset,
    validate_soft_text,
)


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
    @safe_tool("wazuh_list_groups")
    async def wazuh_list_groups(
        search: Optional[str] = types.Field(
            default=None,
            description="Search groups by name",
        ),
        limit: int = types.Field(default=50, description="Maximum groups to return"),
        offset: int = types.Field(default=0, description="Pagination offset"),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        # --- input validation ---
        if search is not None:
            validate_soft_text(search)
        limit = validate_limit(limit, max_limit=500)
        offset = validate_offset(offset)

        data = await client.list_groups(search=search, limit=limit, offset=offset)
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
        if compact_output:
            result = compact(result)
        return format_json(result)

    @mcp.tool(
        name="wazuh_get_group",
        description=(
            "Get detailed information about a specific agent group, "
            "including its configuration and member agents."
        ),
    )
    @safe_tool("wazuh_get_group")
    async def wazuh_get_group(
        group_id: str = types.Field(
            description="Group ID to inspect (e.g., 'default', 'web-servers')",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        validate_soft_text(group_id, param_name="group_id")
        data = await client.get_group(group_id)
        if compact_output:
            data = compact(data)
        return format_json(data)

    @mcp.tool(
        name="wazuh_group_agents",
        description="List all agents belonging to a specific agent group.",
    )
    @safe_tool("wazuh_group_agents")
    async def wazuh_group_agents(
        group_id: str = types.Field(
            description="Group ID to list agents for (e.g., 'web-servers')",
        ),
        limit: int = types.Field(default=50, description="Maximum agents to return"),
        offset: int = types.Field(default=0, description="Pagination offset"),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        # --- input validation ---
        validate_soft_text(group_id, param_name="group_id")
        limit = validate_limit(limit, max_limit=500)
        offset = validate_offset(offset)

        data = await client.group_agents(group_id=group_id, limit=limit, offset=offset)
        items = extract_items(data)
        total = extract_total(data)
        result = paginated_result(
            items,
            total,
            offset,
            limit,
            summary=f"Found {total} agent(s) in group '{group_id}'",
        )
        if compact_output:
            result = compact(result)
        return format_json(result)
