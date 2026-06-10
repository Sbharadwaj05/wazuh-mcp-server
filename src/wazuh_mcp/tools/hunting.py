"""
Threat-hunting tools.

- wazuh_search_events
- wazuh_query_fim
- wazuh_query_vulnerabilities
- wazuh_search_mitre
"""

from __future__ import annotations

from typing import Dict, Optional

import mcp.types as types
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.utils import extract_items, extract_total, format_json, paginated_result


def register_hunting(mcp: FastMCP, client: WazuhClient) -> None:
    """Register all threat-hunting tools on the MCP server."""

    @mcp.tool(
        name="wazuh_search_events",
        description=(
            "Search raw security events across all Wazuh agents. "
            "Use this for deep threat hunting — search for IOCs like IPs, "
            "file hashes, commands, or process names in the raw event stream."
        ),
    )
    async def wazuh_search_events(
        search: str = types.Field(
            description="Search term — IP address, file hash, command, process name, etc.",
        ),
        select: Optional[str] = types.Field(
            default=None,
            description="Comma-separated fields to return (e.g., 'timestamp,agent.name,data.srcip')",
        ),
        sort: Optional[str] = types.Field(
            default=None,
            description="Sort field, prefix with '-' for descending",
        ),
        limit: int = types.Field(
            default=50,
            description="Maximum events to return (1-500)",
        ),
        offset: int = types.Field(
            default=0,
            description="Pagination offset",
        ),
    ) -> str:
        try:
            data = await client.search_events(
                search=search,
                select=select,
                sort=sort or "-timestamp",
                limit=min(limit, 500),
                offset=offset,
            )
            items = extract_items(data)
            total = extract_total(data)
            result = paginated_result(
                items,
                total,
                offset,
                limit,
                summary=f"Searched events for '{search}' — {total} matches",
            )
            return format_json(result)
        except Exception as e:
            return format_json({"error": str(e)})

    @mcp.tool(
        name="wazuh_query_fim",
        description=(
            "Query File Integrity Monitoring (FIM) records. "
            "See what files were added, modified, or deleted on an agent. "
            "Essential for breach impact analysis and configuration drift detection."
        ),
    )
    async def wazuh_query_fim(
        agent_id: str = types.Field(
            description="Agent ID to query FIM records for (e.g., '001')",
        ),
        file_path: Optional[str] = types.Field(
            default=None,
            description="Filter by file path (e.g., '/etc/passwd' or '/var/www/*')",
        ),
        event_type: Optional[str] = types.Field(
            default=None,
            description="Event type filter: 'added', 'modified', or 'deleted'",
        ),
        search: Optional[str] = types.Field(
            default=None,
            description="Free-text search across FIM fields",
        ),
        limit: int = types.Field(
            default=100,
            description="Maximum records to return (1-500)",
        ),
        offset: int = types.Field(
            default=0,
            description="Pagination offset",
        ),
    ) -> str:
        try:
            data = await client.syscheck(
                agent_id=agent_id,
                file_path=file_path,
                event_type=event_type,
                search=search,
                limit=min(limit, 500),
                offset=offset,
            )
            items = extract_items(data)
            total = extract_total(data)

            summary = f"FIM records for agent {agent_id}"
            if event_type:
                summary += f" (type: {event_type})"
            if file_path:
                summary += f" — path: {file_path}"

            result = paginated_result(items, total, offset, limit, summary=summary)
            return format_json(result)
        except Exception as e:
            return format_json({"error": str(e)})

    @mcp.tool(
        name="wazuh_query_vulnerabilities",
        description=(
            "Query the Wazuh vulnerability-detector inventory. "
            "Find CVEs affecting your fleet, filtered by severity, agent, or specific CVE ID."
        ),
    )
    async def wazuh_query_vulnerabilities(
        agent_id: str = types.Field(
            description="Agent ID to query vulnerabilities for (e.g., '001')",
        ),
        cve: Optional[str] = types.Field(
            default=None,
            description="Filter by specific CVE ID (e.g., 'CVE-2024-3094')",
        ),
        severity: Optional[str] = types.Field(
            default=None,
            description="Filter by severity: 'Critical', 'High', 'Medium', or 'Low'",
        ),
        search: Optional[str] = types.Field(
            default=None,
            description="Free-text search (package name, etc.)",
        ),
        limit: int = types.Field(
            default=100,
            description="Maximum vulnerabilities to return (1-500)",
        ),
        offset: int = types.Field(
            default=0,
            description="Pagination offset",
        ),
    ) -> str:
        try:
            data = await client.vulnerabilities(
                agent_id=agent_id,
                cve=cve,
                severity=severity,
                search=search,
                limit=min(limit, 500),
                offset=offset,
            )
            items = extract_items(data)
            total = extract_total(data)

            summary = f"Vulnerabilities for agent {agent_id}"
            if severity:
                summary += f" — severity: {severity}"
            if cve:
                summary += f" — CVE: {cve}"

            result = paginated_result(items, total, offset, limit, summary=summary)
            return format_json(result)
        except Exception as e:
            return format_json({"error": str(e)})

    @mcp.tool(
        name="wazuh_search_mitre",
        description=(
            "Search the MITRE ATT&CK framework as integrated with Wazuh. "
            "Look up techniques, find which Wazuh rules map to a technique, "
            "or discover what techniques are covered by your detection ruleset."
        ),
    )
    async def wazuh_search_mitre(
        search: Optional[str] = types.Field(
            default=None,
            description="Search MITRE techniques by name, ID, or keyword (e.g., 'persistence', 'T1547')",
        ),
        technique_id: Optional[str] = types.Field(
            default=None,
            description="Exact MITRE technique ID (e.g., 'T1547.001')",
        ),
        limit: int = types.Field(
            default=50,
            description="Maximum results (1-200)",
        ),
        offset: int = types.Field(
            default=0,
            description="Pagination offset",
        ),
    ) -> str:
        try:
            data = await client.mitre(
                search=search,
                technique_id=technique_id,
                limit=min(limit, 200),
                offset=offset,
            )
            items = extract_items(data)
            total = extract_total(data)

            summary = "MITRE ATT&CK results"
            if technique_id:
                summary += f" for {technique_id}"
            elif search:
                summary += f" matching '{search}'"

            result = paginated_result(items, total, offset, limit, summary=summary)
            return format_json(result)
        except Exception as e:
            return format_json({"error": str(e)})
