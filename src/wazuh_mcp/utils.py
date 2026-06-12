"""
Shared utilities for the Wazuh MCP server.

- JSON formatting helpers
- Pagination utilities
- Common error handling patterns
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from wazuh_mcp.sanitizer import sanitize


def format_json(data: Any, indent: int = 2) -> str:
    """Pretty-print any object as JSON for LLM consumption, with credential redaction."""
    safe_data = sanitize(data)
    return json.dumps(safe_data, indent=indent, default=str, ensure_ascii=False)


def paginated_result(
    items: List[Dict[str, Any]],
    total: int,
    offset: int,
    limit: int,
    *,
    summary: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a consistent paginated response envelope."""
    result: Dict[str, Any] = {
        "items": items,
        "count": len(items),
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": (offset + limit) < total,
    }
    if summary:
        result["summary"] = summary
    return result


def extract_items(data: Any) -> List[Dict[str, Any]]:
    """Extract affected_items from the Wazuh API envelope, or return as-is."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("affected_items", [])
    return []


def extract_total(data: Any) -> int:
    """Extract total_affected_items from the Wazuh API envelope."""
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        return data.get("total_affected_items", 0)
    return 0


def truncate_for_display(text: str, max_len: int = 4000) -> str:
    """Truncate long text with a note for LLM context windows."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n\n[... truncated {len(text) - max_len} characters]"
