"""
Structured JSON-line logging configuration for the Wazuh MCP server.

Produces one JSON object per line on stderr (or a configurable file)
so log aggregators (ELK, Loki, Datadog, etc.) can ingest them
without regex parsing.

Environment variables
---------------------
``WAZUH_LOG_LEVEL``
    Python log level name (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``).
    Default: ``INFO``.

``WAZUH_LOG_FILE``
    Path to a log file.  When unset, logs go to stderr.
    Default: *unset* (stderr).

Example output line::

    {"timestamp": "2026-06-11T10:15:30.123456+00:00", "level": "INFO",
     "logger": "wazuh-mcp.server", "message": "Starting server",
     "request_id": "a1b2c3d4", "tool_name": "", "duration_ms": null}
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional


class JsonFormatter(logging.Formatter):
    """
    Emit log records as single-line JSON objects.

    Extra fields on the ``LogRecord`` (``request_id``, ``tool_name``,
    ``duration_ms``) are included when present.  This formatter does
    **not** support the legacy ``%(...)`` style — every record becomes
    a standalone JSON object.
    """

    def format(self, record: logging.LogRecord) -> str:

        log_entry: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for key in ("request_id", "tool_name", "duration_ms"):
            val = getattr(record, key, None)
            if val or val == 0:  # include 0 (valid duration) but skip None / ""
                log_entry[key] = val
            else:
                log_entry[key] = None

        # If the exception info is present, serialize it as a string
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


class _ContextFilter(logging.Filter):
    """
    Injects ``request_id`` and ``tool_name`` from :mod:`contextvars`
    into every log record so the :class:`JsonFormatter` can include them.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Lazy import to avoid circular dependency at module load time
        from wazuh_mcp.context import (  # pragma: no cover
            request_id as _rid,
        )
        from wazuh_mcp.context import (
            tool_name as _tool,
        )

        record.request_id = _rid.get() or ""
        record.tool_name = _tool.get() or ""
        return True


def configure_logging(
    level: Optional[str] = None,
    log_file: Optional[str] = None,
) -> None:
    """
    Configure the root logger with JSON-line output.

    Parameters
    ----------
    level:
        Python log level name.  Falls back to ``WAZUH_LOG_LEVEL`` env
        var, then to ``INFO``.
    log_file:
        Path to write logs to.  Falls back to ``WAZUH_LOG_FILE`` env
        var.  When both are unset, logs go to stderr.
    """
    resolved_level: str = (level or os.getenv("WAZUH_LOG_LEVEL", "INFO")).upper()
    resolved_file: str = log_file or os.getenv("WAZUH_LOG_FILE", "")

    handler: logging.Handler
    if resolved_file:
        handler = logging.FileHandler(resolved_file, encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(JsonFormatter())
    handler.addFilter(_ContextFilter())

    root = logging.getLogger()
    root.setLevel(getattr(logging, resolved_level, logging.INFO))

    # Replace any existing handlers (e.g. from a prior basicConfig call)
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
