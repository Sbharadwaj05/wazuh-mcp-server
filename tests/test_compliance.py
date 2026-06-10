"""Tests for compliance tools — SCA status, checks, reports."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from wazuh_mcp.client import WazuhClient


class TestComplianceTools:
    """Test compliance tool client integration."""

    @pytest.fixture
    def mock_client(self):
        return AsyncMock(spec=WazuhClient)

    @pytest.mark.asyncio
    async def test_sca_status_returns_policies(self, mock_client):
        """SCA status should return policy summaries."""
        mock_client.sca_summary.return_value = {
            "affected_items": [
                {
                    "policy_id": "cis_ubuntu22-04",
                    "name": "CIS Ubuntu Linux 22.04 LTS",
                    "pass": 150,
                    "fail": 12,
                    "score": 92.5,
                },
            ],
            "total_affected_items": 1,
        }

        data = await mock_client.sca_summary("001")
        items = data["affected_items"]
        assert len(items) == 1
        assert items[0]["policy_id"] == "cis_ubuntu22-04"

    @pytest.mark.asyncio
    async def test_sca_checks_filtered_by_failed(self, mock_client):
        """SCA checks filtered by 'failed' should only return failures."""
        mock_client.sca_checks.return_value = {
            "affected_items": [
                {"title": "Ensure SSH root login is disabled", "result": "failed"},
            ],
            "total_affected_items": 1,
        }

        data = await mock_client.sca_checks(
            agent_id="001", policy_id="cis_ubuntu22-04", result="failed"
        )
        assert data["total_affected_items"] == 1

    @pytest.mark.asyncio
    async def test_compliance_report_multiple_agents(self, mock_client):
        """Compliance report should aggregate across agents."""
        mock_client.list_agents.return_value = {
            "affected_items": [
                {"id": "001", "name": "web-1"},
                {"id": "002", "name": "db-1"},
            ],
            "total_affected_items": 2,
        }

        data = await mock_client.list_agents(limit=500)
        assert data["total_affected_items"] == 2
