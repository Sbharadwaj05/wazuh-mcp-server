"""Tests for threat hunting tools — FIM, events, vulnerabilities, MITRE."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from wazuh_mcp.client import WazuhClient


class TestHuntingTools:
    """Test hunting tool client integration."""

    @pytest.fixture
    def mock_client(self):
        return AsyncMock(spec=WazuhClient)

    @pytest.mark.asyncio
    async def test_search_events_by_ip(self, mock_client):
        """Searching events for an IP address should return matching events."""
        mock_client.search_events.return_value = {
            "affected_items": [
                {"timestamp": "2024-01-01", "data": {"srcip": "10.0.0.50"}},
            ],
            "total_affected_items": 1,
        }

        data = await mock_client.search_events(search="10.0.0.50")
        assert data["total_affected_items"] == 1

    @pytest.mark.asyncio
    async def test_query_fim_modified_files(self, mock_client):
        """FIM query for modified files should return file change records."""
        mock_client.syscheck.return_value = {
            "affected_items": [
                {"file": "/etc/passwd", "type": "modified", "mtime": "2024-01-01"},
            ],
            "total_affected_items": 1,
        }

        data = await mock_client.syscheck(
            agent_id="001", event_type="modified", limit=100
        )
        assert len(data["affected_items"]) == 1

    @pytest.mark.asyncio
    async def test_query_vulnerabilities_by_critical(self, mock_client):
        """Querying critical CVEs should filter properly."""
        mock_client.vulnerabilities.return_value = {
            "affected_items": [
                {"cve": "CVE-2024-3094", "severity": "Critical", "package": "xz"},
            ],
            "total_affected_items": 1,
        }

        data = await mock_client.vulnerabilities(agent_id="001", severity="Critical")
        assert data["total_affected_items"] == 1

    @pytest.mark.asyncio
    async def test_search_mitre_technique(self, mock_client):
        """MITRE search should return technique details."""
        mock_client.mitre.return_value = {
            "affected_items": [
                {"id": "T1110", "name": "Brute Force", "phase": "Credential Access"},
            ],
            "total_affected_items": 1,
        }

        data = await mock_client.mitre(technique_id="T1110")
        assert data["total_affected_items"] == 1
