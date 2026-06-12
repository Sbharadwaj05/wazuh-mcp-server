"""
Safe-tool decorator that wraps async MCP tool functions with structured
error handling, RBAC enforcement, and rate limiting.
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

# Lazy imports to avoid circular dependencies at module load
_rbac = None
_limiter = None


def _get_rbac():
    global _rbac
    if _rbac is None:
        from wazuh_mcp.rbac import get_rbac_enforcer

        _rbac = get_rbac_enforcer()
    return _rbac


def _get_limiter():
    global _limiter
    if _limiter is None:
        from wazuh_mcp.rate_limiter import get_rate_limiter

        _limiter = get_rate_limiter()
    return _limiter


def safe_tool(tool_name: str):
    """
    Decorator that wraps an async MCP tool function.

    Enforces:
    - RBAC: rejects the call if the configured role lacks access
    - Rate limiting: rejects if the token bucket is empty
    - Structured error responses for known exception types
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # --- RBAC gate ---
            rbac = _get_rbac()
            if rbac._enabled and not rbac.is_allowed(tool_name):
                logger.warning("RBAC blocked tool '%s'", tool_name)
                return format_json(
                    {
                        "error": {
                            "type": "AccessDenied",
                            "message": f"Tool '{tool_name}' is not allowed for the current RBAC role.",
                        }
                    }
                )

            # --- Rate limit gate ---
            limiter = _get_limiter()
            if not limiter.check(tool_name):
                logger.warning("Rate limit hit for '%s'", tool_name)
                return format_json(
                    {
                        "error": {
                            "type": "RateLimited",
                            "message": f"Tool '{tool_name}' is rate-limited. Retry shortly.",
                        }
                    }
                )

            # --- Execute ---
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
