"""
Alert triage & investigation tools.

- wazuh_list_alerts
- wazuh_get_alert
- wazuh_alert_summary
"""

from __future__ import annotations

from collections import Counter
from typing import Optional

import mcp.types as types
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.utils import extract_items, extract_total, format_json, paginated_result


def register_alerts(mcp: FastMCP, client: WazuhClient) -> None:
    """Register all alert-related tools on the MCP server."""

    @mcp.tool(
        name="wazuh_list_alerts",
        description=(
            "Query Wazuh security alerts with powerful filters. "
            "Use this to triage incidents, hunt for specific threat patterns, "
            "or get an overview of recent security events."
        ),
    )
    async def wazuh_list_alerts(
        agent_id: Optional[str] = types.Field(
            default=None,
            description="Filter alerts to a specific agent ID (e.g., '001')",
        ),
        agents_list: Optional[str] = types.Field(
            default=None,
            description="Comma-separated agent IDs to filter (e.g., '001,002,003')",
        ),
        min_level: Optional[int] = types.Field(
            default=None,
            description="Minimum rule level (3-15). Higher = more severe. Use 12+ for critical only.",
        ),
        rule_id: Optional[str] = types.Field(
            default=None,
            description="Filter by a specific Wazuh rule ID (e.g., '5710' for SSH brute force)",
        ),
        rule_ids: Optional[str] = types.Field(
            default=None,
            description="Comma-separated rule IDs (e.g., '5710,5712,5760')",
        ),
        mitre_id: Optional[str] = types.Field(
            default=None,
            description="Filter by MITRE ATT&CK technique ID (e.g., 'T1110' for brute force)",
        ),
        search: Optional[str] = types.Field(
            default=None,
            description="Free-text search across alert fields (IP, hostname, command, etc.)",
        ),
        sort: Optional[str] = types.Field(
            default=None,
            description="Sort field, prefix with '-' for descending (e.g., '-timestamp')",
        ),
        limit: int = types.Field(
            default=50,
            description="Maximum number of alerts to return (1-500)",
        ),
        offset: int = types.Field(
            default=0,
            description="Pagination offset for scrolling through results",
        ),
    ) -> str:
        try:
            data = await client.list_alerts(
                agent_id=agent_id,
                agents_list=agents_list,
                min_level=min_level,
                rule_id=rule_id,
                rule_ids=rule_ids,
                mitre_id=mitre_id,
                search=search,
                sort=sort or "-timestamp",
                limit=min(limit, 500),
                offset=offset,
            )
            items = extract_items(data)
            total = extract_total(data)

            # Add a human-readable summary
            summary_parts = [f"Found {total} alert(s)"]
            if min_level:
                summary_parts.append(f"with level >= {min_level}")
            if rule_id:
                summary_parts.append(f"for rule {rule_id}")
            if mitre_id:
                summary_parts.append(f"mapped to {mitre_id}")

            result = paginated_result(
                items, total, offset, limit, summary=" | ".join(summary_parts)
            )
            return format_json(result)

        except Exception as e:
            return format_json({"error": str(e)})

    @mcp.tool(
        name="wazuh_get_alert",
        description=(
            "Fetch a single Wazuh alert by its ID with full contextual detail. "
            "Use this when investigating a specific alert from wazuh_list_alerts results."
        ),
    )
    async def wazuh_get_alert(
        alert_id: str = types.Field(
            description="The alert ID to retrieve (from wazuh_list_alerts output)",
        ),
    ) -> str:
        try:
            alert = await client.get_alert(alert_id)
            return format_json(alert)
        except Exception as e:
            return format_json({"error": str(e)})

    @mcp.tool(
        name="wazuh_alert_summary",
        description=(
            "Get a high-level summary of recent alerts: severity distribution, "
            "top attacking IPs, most triggered rules, and MITRE technique coverage. "
            "Use this as the first step in security posture assessment or shift handoff."
        ),
    )
    async def wazuh_alert_summary(
        hours_back: int = types.Field(
            default=24,
            description="Number of hours to look back for the summary (default: 24)",
        ),
        min_level: int = types.Field(
            default=7,
            description="Minimum alert level to include (default: 7, moderate and above)",
        ),
    ) -> str:
        try:
            data = await client.list_alerts(
                min_level=min_level,
                sort="-timestamp",
                limit=500,
                select="rule.id,rule.level,rule.description,rule.mitre.id,agent.id,agent.name,data.srcip,timestamp",
            )
            items = extract_items(data)
            total = extract_total(data)

            if not items:
                return format_json(
                    {
                        "summary": f"No alerts level >= {min_level} in the last {hours_back}h",
                        "total": 0,
                    }
                )

            # Compute aggregates
            level_counts = Counter()
            rule_counts: Counter = Counter()
            mitre_counts: Counter = Counter()
            agent_counts: Counter = Counter()
            srcip_counts: Counter = Counter()

            for alert in items:
                rule = alert.get("rule", {})
                agent = alert.get("agent", {})
                data_fields = alert.get("data", {})

                level = rule.get("level", "unknown")
                rule_desc = rule.get("description", "unknown")
                level_counts[level] += 1
                rule_counts[rule_desc] += 1

                for mitre_entry in rule.get("mitre", {}).get("id", []) or []:
                    mitre_counts[mitre_entry] += 1

                agent_name = agent.get("name", "unknown")
                agent_counts[agent_name] += 1

                srcip = data_fields.get("srcip")
                if srcip:
                    srcip_counts[srcip] += 1

            summary = {
                "total_alerts_analyzed": len(items),
                "total_alerts_available": total,
                "time_window_hours": hours_back,
                "min_level": min_level,
                "severity_distribution": dict(level_counts.most_common()),
                "top_rules": dict(rule_counts.most_common(10)),
                "top_mitre_techniques": dict(mitre_counts.most_common(10)),
                "top_agents": dict(agent_counts.most_common(10)),
                "top_source_ips": dict(srcip_counts.most_common(10)),
            }
            return format_json(summary)

        except Exception as e:
            return format_json({"error": str(e)})
