"""
Immutable audit logging for all destructive MCP actions.

Every call to ``wazuh_run_active_response`` and ``wazuh_agent_command``
is recorded as an append-only, structured JSON log entry. The log
file is opened in append mode and never truncated — treat it as
an immutable audit trail.

Log format (one JSON object per line)::

    {
      "timestamp": "2024-01-01T00:00:00Z",
      "tool": "wazuh_run_active_response",
      "action": "firewall-drop on agent 001",
      "parameters": {"agent_id": "001", "command": "firewall-drop", ...},
      "result_summary": {"status": "EXECUTED", ...},
      "request_id": "a1b2c3d4",
      "mcp_session_id": "abc123",
      "source": "claude-desktop"
    }

Rotation
--------
When the audit file exceeds ``WAZUH_AUDIT_MAX_SIZE_MB`` (default 10 MB),
it is rotated to ``audit-YYYY-MM-DD.jsonl`` in the same directory and a
fresh ``audit.jsonl`` is started.  Rotation is performed inside the
write lock so no entries are lost.

Production deployment
---------------------
For production use, set ``WAZUH_AUDIT_LOG`` to a secure, write-once
location outside the user home directory, e.g.::

    export WAZUH_AUDIT_LOG=/var/log/wazuh-mcp/audit.jsonl

Alternatively, send audit events to syslog by piping to ``logger`` or
using a syslog handler.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("wazuh-mcp.audit")

# ---- Path resolution ----------------------------------------------------


def _resolve_audit_path() -> Path:
    """Return the audit log path from env or the default."""
    default = str(Path.home() / ".wazuh-mcp" / "audit.jsonl")
    return Path(os.getenv("WAZUH_AUDIT_LOG", default))


AUDIT_LOG_PATH = _resolve_audit_path()

# Ensure parent directory exists
AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# ---- Max size (MB) before rotation ---------------------------------------


def _resolve_max_size_mb() -> int:
    raw = os.getenv("WAZUH_AUDIT_MAX_SIZE_MB", "10")
    try:
        val = int(raw)
        if val < 1:
            logger.warning("WAZUH_AUDIT_MAX_SIZE_MB=%s is too small; using 1 MB", raw)
            return 1
        return val
    except ValueError:
        logger.warning("Invalid WAZUH_AUDIT_MAX_SIZE_MB=%r; using default 10", raw)
        return 10


AUDIT_MAX_SIZE_MB = _resolve_max_size_mb()
AUDIT_MAX_SIZE_BYTES = AUDIT_MAX_SIZE_MB * 1024 * 1024

# ---- Startup warning for home-directory paths ---------------------------

_HOME = Path.home()
try:
    _in_home = AUDIT_LOG_PATH.resolve().is_relative_to(_HOME.resolve())
except AttributeError:
    # is_relative_to added in Python 3.9; fallback for older versions
    _in_home = str(AUDIT_LOG_PATH.resolve()).startswith(str(_HOME.resolve()))

if _in_home:
    logger.warning(
        "Audit log is stored in your home directory (%s). "
        "For production deployments, set WAZUH_AUDIT_LOG to a secure "
        "location such as /var/log/wazuh-mcp/audit.jsonl, or pipe audit "
        "events to syslog.",
        AUDIT_LOG_PATH,
    )

_write_lock = threading.Lock()


# ---- Rotation -----------------------------------------------------------


def _rotate_if_needed() -> None:
    """
    Atomically rotate the audit log if it exceeds the size threshold.

    The current ``audit.jsonl`` is renamed to ``audit-YYYY-MM-DD.jsonl``.
    If a file with that name already exists, an incrementing suffix
    (``-2``, ``-3``, …) is appended to avoid overwriting previous
    rotations.
    """
    try:
        size = AUDIT_LOG_PATH.stat().st_size
    except FileNotFoundError:
        return  # nothing to rotate yet

    if size < AUDIT_MAX_SIZE_BYTES:
        return

    # Build destination name: audit-YYYY-MM-DD.jsonl
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    stem = AUDIT_LOG_PATH.stem  # "audit"
    suffix = AUDIT_LOG_PATH.suffix  # ".jsonl"
    dest_dir = AUDIT_LOG_PATH.parent
    dest = dest_dir / f"{stem}-{today}{suffix}"

    # Avoid overwriting earlier rotations from the same day
    counter = 1
    while dest.exists():
        counter += 1
        dest = dest_dir / f"{stem}-{today}-{counter}{suffix}"

    # Atomic rename on the same filesystem
    try:
        AUDIT_LOG_PATH.rename(dest)
        logger.info("Rotated audit log to %s (%.1f MB)", dest, size / (1024 * 1024))
    except OSError as exc:
        logger.error("Failed to rotate audit log: %s", exc)


# ---- Core API -----------------------------------------------------------


def record_action(
    tool_name: str,
    action: str,
    parameters: Dict[str, Any],
    result: Dict[str, Any],
    *,
    mcp_session_id: Optional[str] = None,
    source: str = "mcp-client",
    request_id: Optional[str] = None,
) -> None:
    """
    Append an immutable audit entry to the audit log.

    This is called automatically by the safety-gated tools in
    ``response.py``.  External callers can also use it directly for
    custom audit needs.

    Thread-safe via a mutex — multiple concurrent tool calls
    won't corrupt the log.
    """
    # Resolve request_id from context if not explicitly passed
    if request_id is None:
        from wazuh_mcp.context import request_id as _ctx_rid

        request_id = _ctx_rid.get() or None

    entry: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool_name,
        "action": action,
        "parameters": parameters,
        "result_summary": {
            k: v for k, v in result.items() if k not in ("raw_response", "full_output")
        },
        "request_id": request_id,
        "mcp_session_id": mcp_session_id,
        "source": source,
    }

    with _write_lock:
        try:
            _rotate_if_needed()
            with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.error("Failed to write audit log: %s", exc)


def get_audit_log_path() -> Path:
    """Return the current audit log file path."""
    return AUDIT_LOG_PATH


def get_audit_max_size_mb() -> int:
    """Return the configured rotation threshold in MB."""
    return AUDIT_MAX_SIZE_MB


def tail_audit_log(lines: int = 50) -> list[Dict[str, Any]]:
    """Read the last *N* lines of the audit log (for inspection)."""
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
