"""
CDB (Constant Database) list tools.

- wazuh_list_cdb_lists
- wazuh_get_cdb_list
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


def register_lists(mcp: FastMCP, client: WazuhClient) -> None:
    """Register CDB list management tools."""

    @mcp.tool(
        name="wazuh_list_cdb_lists",
        description=(
            "List all CDB (Constant Database) lists configured in Wazuh. "
            "CDB lists store key-value data used by rules — IP blocklists, "
            "user whitelists, IOC databases, etc. Essential for understanding "
            "what threat intelligence feeds are active."
        ),
    )
    @safe_tool("wazuh_list_cdb_lists")
    async def wazuh_list_cdb_lists(
        search: Optional[str] = types.Field(
            default=None,
            description="Search lists by name",
        ),
        limit: int = types.Field(default=50, description="Maximum lists to return"),
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

        data = await client.list_cdb_lists(search=search, limit=limit, offset=offset)
        items = extract_items(data)
        total = extract_total(data)
        result = paginated_result(
            items,
            total,
            offset,
            limit,
            summary=f"Found {total} CDB list(s)",
        )
        if compact_output:
            result = compact(result)
        return format_json(result)

    @mcp.tool(
        name="wazuh_get_cdb_list",
        description=(
            "Read the contents of a specific CDB list. CDB lists are used "
            "for IP reputation, user whitelists, IOC matching, and more. "
            "Returns the key-value entries in the list."
        ),
    )
    @safe_tool("wazuh_get_cdb_list")
    async def wazuh_get_cdb_list(
        list_name: str = types.Field(
            description="CDB list name to read (e.g., 'audit-keys', 'security-eventchannel')",
        ),
        search: Optional[str] = types.Field(
            default=None,
            description="Search within list entries",
        ),
        limit: int = types.Field(default=200, description="Maximum entries to return"),
        offset: int = types.Field(default=0, description="Pagination offset"),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        # --- input validation ---
        validate_soft_text(list_name, param_name="list_name")
        if search is not None:
            validate_soft_text(search)
        limit = validate_limit(limit, max_limit=1000)
        offset = validate_offset(offset)

        data = await client.get_cdb_list(
            list_name=list_name,
            search=search,
            limit=limit,
            offset=offset,
        )
        items = extract_items(data)
        total = extract_total(data)
        result = paginated_result(
            items,
            total,
            offset,
            limit,
            summary=f"CDB list '{list_name}' — {total} entries",
        )
        if compact_output:
            result = compact(result)
        return format_json(result)
