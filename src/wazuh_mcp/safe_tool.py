"""
Safe-tool decorator that wraps async MCP tool functions with structured
error handling, preventing raw tracebacks from leaking to the LLM.
"""

from __future__ import annotations

import functools
import logging
from typing import Callable

from wazuh_mcp.errors import (
    AuthError,
    RateLimitError,
    ToolError,
    ValidationError,
    WazuhAPIError,
)
from wazuh_mcp.utils import format_json

logger = logging.getLogger("wazuh-mcp.safe_tool")


def safe_tool(tool_name: str):
    """
    Decorator that wraps an async MCP tool function.

    Catches known exception types and returns structured JSON error
    responses of the form ``{"error": {"type": "...", "message": "..."}}``.

    - :class:`ValidationError` — invalid input (logged at WARNING)
    - :class:`RateLimitError` — rate limit (logged at WARNING)
    - :class:`AuthError` — auth failure (logged at ERROR)
    - :class:`WazuhAPIError` — upstream API error (logged at ERROR)
    - :class:`ValueError` — from validators, converted to ValidationError
    - :class:`Exception` — last resort, returned as :class:`ToolError`
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except ValidationError as e:
                logger.warning("Validation error in %s: %s", tool_name, e.message)
                return format_json({"error": e.to_dict()})
            except RateLimitError as e:
                logger.warning("Rate limit in %s: %s", tool_name, e.message)
                return format_json({"error": e.to_dict()})
            except AuthError as e:
                logger.error("Auth error in %s: %s", tool_name, e.message)
                return format_json({"error": e.to_dict()})
            except WazuhAPIError as e:
                logger.error("API error in %s: %s", tool_name, e.message)
                return format_json({"error": e.to_dict()})
            except ValueError as e:
                # Validators raise ValueError — promote to ValidationError
                logger.warning("Validation error in %s: %s", tool_name, str(e))
                return format_json({"error": ValidationError(str(e)).to_dict()})
            except Exception as e:
                logger.exception("Unhandled error in %s", tool_name)
                return format_json(
                    {"error": ToolError(tool_name=tool_name, details=str(e)).to_dict()}
                )

        return wrapper

    return decorator
