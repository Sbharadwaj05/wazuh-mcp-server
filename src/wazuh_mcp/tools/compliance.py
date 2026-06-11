"""
Compliance assessment tools.

- wazuh_sca_status
- wazuh_sca_checks
- wazuh_compliance_report
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
    validate_agent_id,
    validate_limit,
    validate_offset,
    validate_soft_text,
)


def register_compliance(mcp: FastMCP, client: WazuhClient) -> None:
    """Register all compliance-related tools on the MCP server."""

    @mcp.tool(
        name="wazuh_sca_status",
        description=(
            "Get the Security Configuration Assessment (SCA) compliance status "
            "for an agent. Shows which policies are applied, pass/fail counts, "
            "and overall compliance scores."
        ),
    )
    @safe_tool("wazuh_sca_status")
    async def wazuh_sca_status(
        agent_id: str = types.Field(
            default="000",
            description="Agent ID (default: '000' for the manager itself)",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        validate_agent_id(agent_id)

        data = await client.sca_summary(agent_id)
        items = extract_items(data)

        if not items:
            return format_json(
                {
                    "summary": f"No SCA data found for agent {agent_id}",
                    "agent_id": agent_id,
                }
            )

        # Build per-policy summary
        policies = []
        for policy in items:
            policies.append(
                {
                    "policy_id": policy.get("policy_id", "unknown"),
                    "name": policy.get("name", policy.get("policy_id", "unknown")),
                    "description": policy.get("description", ""),
                    "references": policy.get("references", ""),
                    "pass": policy.get("pass", 0),
                    "fail": policy.get("fail", 0),
                    "invalid": policy.get("invalid", 0),
                    "total_checks": policy.get("total_checks", 0),
                    "score": policy.get("score", 0),
                    "end_scan": policy.get("end_scan", ""),
                }
            )

        overall = {
            "agent_id": agent_id,
            "policies": policies,
            "total_policies": len(policies),
        }
        if compact_output:
            overall = compact(overall)
        return format_json(overall)

    @mcp.tool(
        name="wazuh_sca_checks",
        description=(
            "Get detailed SCA check results — see exactly which compliance "
            "checks passed or failed on an agent. Filter by policy, search, "
            "or result status."
        ),
    )
    @safe_tool("wazuh_sca_checks")
    async def wazuh_sca_checks(
        agent_id: str = types.Field(
            description="Agent ID to query (e.g., '001')",
        ),
        policy_id: Optional[str] = types.Field(
            default=None,
            description="Filter by SCA policy ID (from wazuh_sca_status output)",
        ),
        result: Optional[str] = types.Field(
            default=None,
            description="Filter by result: 'passed' or 'failed'",
        ),
        search: Optional[str] = types.Field(
            default=None,
            description="Search within check titles, rationales, or descriptions",
        ),
        limit: int = types.Field(
            default=100,
            description="Maximum checks to return (1-500)",
        ),
        offset: int = types.Field(
            default=0,
            description="Pagination offset",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        # --- input validation ---
        validate_agent_id(agent_id)
        if policy_id is not None:
            validate_soft_text(policy_id, param_name="policy_id")
        if result is not None:
            validate_soft_text(result, param_name="result")
        if search is not None:
            validate_soft_text(search)
        limit = validate_limit(limit, max_limit=500)
        offset = validate_offset(offset)

        data = await client.sca_checks(
            agent_id=agent_id,
            policy_id=policy_id,
            result=result,
            search=search,
            limit=limit,
            offset=offset,
        )
        items = extract_items(data)
        total = extract_total(data)

        summary = f"SCA checks for agent {agent_id}"
        if policy_id:
            summary += f" (policy: {policy_id})"
        if result:
            summary += f" — {result}"

        result_payload = paginated_result(items, total, offset, limit, summary=summary)
        if compact_output:
            result_payload = compact(result_payload)
        return format_json(result_payload)

    @mcp.tool(
        name="wazuh_compliance_report",
        description=(
            "Generate a compliance summary report across agents. Shows "
            "which agents have SCA enabled, their compliance scores, and "
            "failed-check counts grouped by policy. Ideal for audit prep."
        ),
    )
    @safe_tool("wazuh_compliance_report")
    async def wazuh_compliance_report(
        agent_ids: Optional[str] = types.Field(
            default=None,
            description="Comma-separated agent IDs or agent groups (default: fetch all from agent list)",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        if agent_ids is not None:
            validate_soft_text(agent_ids, param_name="agent_ids")

        # Resolve agent IDs
        if agent_ids:
            resolved_ids = [a.strip() for a in agent_ids.split(",") if a.strip()]
        else:
            agents_data = await client.list_agents(limit=500)
            agent_items = extract_items(agents_data)
            resolved_ids = [str(a.get("id", "")) for a in agent_items if a.get("id")]

        report_lines: list[dict] = []
        total_pass = 0
        total_fail = 0
        total_agents_with_sca = 0

        for agent_id in resolved_ids:
            try:
                data = await client.sca_summary(agent_id)
                policies = extract_items(data)
                if not policies:
                    continue

                total_agents_with_sca += 1
                for policy in policies:
                    p_pass = policy.get("pass", 0) or 0
                    p_fail = policy.get("fail", 0) or 0
                    total_pass += p_pass
                    total_fail += p_fail
                    report_lines.append(
                        {
                            "agent_id": agent_id,
                            "policy_id": policy.get("policy_id", "unknown"),
                            "policy_name": policy.get("name", ""),
                            "pass": p_pass,
                            "fail": p_fail,
                            "score": policy.get("score", 0),
                            "last_scan": policy.get("end_scan", ""),
                        }
                    )
            except Exception:
                continue  # agent may not support SCA

        report = {
            "agents_with_sca": total_agents_with_sca,
            "total_agents_checked": len(resolved_ids),
            "total_checks_passed": total_pass,
            "total_checks_failed": total_fail,
            "overall_pass_rate": (
                f"{(total_pass / (total_pass + total_fail) * 100):.1f}%"
                if (total_pass + total_fail) > 0
                else "N/A"
            ),
            "per_policy_breakdown": report_lines,
        }
        if compact_output:
            report = compact(report)
        return format_json(report)
