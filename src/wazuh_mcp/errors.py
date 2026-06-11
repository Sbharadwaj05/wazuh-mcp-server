"""
Structured error hierarchy for Wazuh MCP tools.

All errors serialize to structured JSON via ``to_dict()``, making them
LLM-friendly and consistent across all tool handlers.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class WazuhMCPError(Exception):
    """Base exception for all Wazuh MCP errors."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a structured JSON-serializable dictionary."""
        return {"type": self.__class__.__name__, "message": self.message}


class WazuhAPIError(WazuhMCPError):
    """
    Wraps a Wazuh API error response.

    Raised by :class:`WazuhClient` when the Wazuh REST API returns a
    non-zero error code or an HTTP error status.
    """

    def __init__(self, status_code: int, message: str, details: Any = None):
        self.status_code = status_code
        self.details = details
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result["status_code"] = self.status_code
        if self.details:
            result["details"] = self.details
        return result


class ValidationError(WazuhMCPError):
    """Invalid or malicious input parameter detected by validators."""


class RateLimitError(WazuhMCPError):
    """Rate limit exceeded on the Wazuh API."""


class AuthError(WazuhMCPError):
    """Authentication or authorization failure."""


class ToolError(WazuhMCPError):
    """
    Tool-level failure with contextual metadata.

    Used as a last-resort catch-all when an unexpected exception occurs
    inside a tool handler.
    """

    def __init__(
        self,
        tool_name: str,
        details: str = "",
        message: Optional[str] = None,
    ):
        self.tool_name = tool_name
        self.details = details
        super().__init__(message or details)

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result["tool_name"] = self.tool_name
        if self.details:
            result["details"] = self.details
        return result
