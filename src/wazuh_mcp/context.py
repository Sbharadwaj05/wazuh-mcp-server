"""
Request-scoped context variables for tracing tool invocations.

Uses Python :mod:`contextvars` to propagate ``request_id`` and
``tool_name`` through async call chains without explicit argument
passing. This enables structured JSON-line logging to include a
correlation ID for every operation.

Typical usage in a tool handler::

    from wazuh_mcp.context import set_tool_context

    async def my_tool(...):
        set_tool_context("my_tool")
        # All subsequent log calls inside this async scope
        # automatically include request_id and tool_name.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar

#: Per-invocation correlation ID.  A fresh UUID is generated for every
#: MCP tool call so all logs emitted during that call can be grouped.
request_id: ContextVar[str] = ContextVar("request_id", default="")

#: Name of the currently executing MCP tool, if any.
tool_name: ContextVar[str] = ContextVar("tool_name", default="")


def generate_request_id() -> str:
    """Return a new short request ID (8 hex chars) and store it in context."""
    rid = uuid.uuid4().hex[:8]
    request_id.set(rid)
    return rid


def set_tool_context(name: str) -> str:
    """
    Set both ``request_id`` and ``tool_name`` for the current invocation.

    Returns the generated request ID so it can be used as a return value
    or logged explicitly.
    """
    tool_name.set(name)
    return generate_request_id()


def clear_tool_context() -> None:
    """Reset both context variables (useful in tests or cleanup)."""
    request_id.set("")
    tool_name.set("")
