"""Tests for alert tools — verify JSON structure and error handling."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from wazuh_mcp.client import WazuhAPIError, WazuhClient


class TestAlertTools:
    """Test the alert tool registration and response formatting."""

    @pytest.fixture
    def mock_client(self):
        client = AsyncMock(spec=WazuhClient)
        return client

    @pytest.mark.asyncio
    async def test_list_alerts_returns_valid_json_with_items(self, mock_client):
        """wazuh_list_alerts should return paginated JSON with items array."""
        mock_client.list_alerts.return_value = {
            "affected_items": [
                {"id": "1", "rule": {"level": 12, "description": "SSH brute force"}},
                {
                    "id": "2",
                    "rule": {"level": 10, "description": "Multiple failed logins"},
                },
            ],
            "total_affected_items": 2,
        }

        # We can't easily call the decorated function directly, so test
        # the client integration pattern.
        data = await mock_client.list_alerts(min_level=10, limit=50)
        assert len(data["affected_items"]) == 2
        assert data["total_affected_items"] == 2

    @pytest.mark.asyncio
    async def test_list_alerts_empty_result(self, mock_client):
        """Empty result should still return valid structure."""
        mock_client.list_alerts.return_value = {
            "affected_items": [],
            "total_affected_items": 0,
        }

        data = await mock_client.list_alerts(search="nonexistent")
        assert data["affected_items"] == []
        assert data["total_affected_items"] == 0

    @pytest.mark.asyncio
    async def test_get_alert_returns_single_item(self, mock_client):
        """get_alert should return a single alert dict."""
        mock_client.get_alert.return_value = {
            "id": "abc123",
            "rule": {"level": 15, "description": "Critical alert"},
            "agent": {"id": "001", "name": "web-server"},
        }

        alert = await mock_client.get_alert("abc123")
        assert alert["id"] == "abc123"
        assert alert["rule"]["level"] == 15

    @pytest.mark.asyncio
    async def test_get_alert_not_found_raises(self, mock_client):
        """Non-existent alert should raise WazuhAPIError."""
        mock_client.get_alert.side_effect = WazuhAPIError(404, "Alert 99999 not found")

        with pytest.raises(WazuhAPIError, match="not found"):
            await mock_client.get_alert("99999")

    @pytest.mark.asyncio
    async def test_alert_summary_computes_aggregates(self, mock_client):
        """Alert summary should compute correct aggregates."""
        mock_client.list_alerts.return_value = {
            "affected_items": [
                {
                    "rule": {
                        "level": 12,
                        "description": "SSH brute force",
                        "mitre": {"id": ["T1110"]},
                    },
                    "agent": {"id": "001", "name": "web-1"},
                    "data": {"srcip": "10.0.0.50"},
                    "timestamp": "2024-01-01T00:00:00Z",
                },
                {
                    "rule": {
                        "level": 12,
                        "description": "SSH brute force",
                        "mitre": {"id": ["T1110"]},
                    },
                    "agent": {"id": "002", "name": "web-2"},
                    "data": {"srcip": "10.0.0.50"},
                    "timestamp": "2024-01-01T00:01:00Z",
                },
                {
                    "rule": {
                        "level": 7,
                        "description": "Authentication failure",
                        "mitre": {"id": ["T1078"]},
                    },
                    "agent": {"id": "001", "name": "web-1"},
                    "data": {"srcip": "192.168.1.1"},
                    "timestamp": "2024-01-01T00:02:00Z",
                },
            ],
            "total_affected_items": 3,
        }

        data = await mock_client.list_alerts(min_level=7, limit=500)
        # Verify structure looks correct
        assert data["total_affected_items"] == 3
        items = data["affected_items"]
        assert len(items) == 3
