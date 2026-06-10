"""
Immutable audit logging for all destructive MCP actions.

Every call to wazuh_run_active_response and wazuh_agent_command
is recorded as an append-only, structured JSON log entry. The log
file is opened in append mode and never truncated — treat it as
an immutable audit trail.

Log format (one JSON object per line):
{
  "timestamp": "2024-01-01T00:00:00Z",
  "tool": "wazuh_run_active_response",
  "action": "firewall-drop on agent 001",
  "parameters": {"agent_id": "001", "command": "firewall-drop", ...},
  "result": {"status": "EXECUTED", ...},
  "mcp_session_id": "abc123",
  "source": "claude-desktop"
}
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("wazuh-mcp.audit")

# Default audit log location — override with WAZUH_AUDIT_LOG env var
AUDIT_LOG_PATH = Path(
    os.getenv("WAZUH_AUDIT_LOG", str(Path.home() / ".wazuh-mcp" / "audit.jsonl"))
)

# Ensure parent directory exists
AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

_write_lock = threading.Lock()


def record_action(
    tool_name: str,
    action: str,
    parameters: Dict[str, Any],
    result: Dict[str, Any],
    *,
    mcp_session_id: Optional[str] = None,
    source: str = "mcp-client",
) -> None:
    """
    Append an immutable audit entry to the audit log.

    This is called automatically by the safety-gated tools in
    response.py. External callers can also use it directly for
    custom audit needs.

    Thread-safe via a mutex — multiple concurrent tool calls
    won't corrupt the log.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool_name,
        "action": action,
        "parameters": parameters,
        "result_summary": {
            k: v for k, v in result.items() if k not in ("raw_response", "full_output")
        },
        "mcp_session_id": mcp_session_id,
        "source": source,
    }

    with _write_lock:
        try:
            with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.error("Failed to write audit log: %s", exc)


def get_audit_log_path() -> Path:
    """Return the current audit log file path."""
    return AUDIT_LOG_PATH


def tail_audit_log(lines: int = 50) -> list[Dict[str, Any]]:
    """Read the last N lines of the audit log (for inspection)."""
    entries: list[Dict[str, Any]] = []
    try:
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
            all_lines = f.readlines()
            for line in all_lines[-lines:]:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        entries.append({"raw": line, "error": "parse_failure"})
    except FileNotFoundError:
        pass
    return entries
