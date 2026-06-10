"""
In-memory rate limiter to prevent API overload from aggressive
AI tool calling.

Uses a sliding-window algorithm: each tool invocation consumes
a token from a per-tool bucket. Buckets refill at a configurable
rate. When a bucket is empty, the tool call is rejected with
a 429-style response.

Configure via environment variables:
  WAZUH_RATE_LIMIT_TOKENS   — max burst (default: 30)
  WAZUH_RATE_LIMIT_PERIOD   — refill window in seconds (default: 60)

Which gives: 30 requests per 60 seconds per tool, with burst
capacity of 30.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Dict, Optional


class TokenBucket:
    """Classic token-bucket rate limiter (thread-safe)."""

    def __init__(self, max_tokens: int, refill_period: float) -> None:
        self.max_tokens = max_tokens
        self.refill_period = refill_period  # seconds to fully refill
        self._tokens = float(max_tokens)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume *tokens*. Returns True if allowed, False if rate-limited."""
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        if elapsed > 0:
            self._tokens = min(
                self.max_tokens,
                self._tokens + (elapsed / self.refill_period) * self.max_tokens,
            )
        self._last_refill = now

    @property
    def available(self) -> float:
        with self._lock:
            self._refill()
            return self._tokens


class RateLimiter:
    """
    Per-tool rate limiter.

    Each tool name gets its own TokenBucket. Tools not explicitly
    configured share a global default bucket.
    """

    def __init__(
        self,
        max_tokens: int = 30,
        refill_period: float = 60.0,
    ) -> None:
        self._default_max = max_tokens
        self._default_period = refill_period
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def _get_bucket(self, tool_name: str) -> TokenBucket:
        """Get or create a bucket for a tool."""
        if tool_name not in self._buckets:
            with self._lock:
                if tool_name not in self._buckets:
                    # Destructive tools get stricter limits
                    if tool_name in (
                        "wazuh_run_active_response",
                        "wazuh_agent_command",
                    ):
                        bucket = TokenBucket(max_tokens=5, refill_period=120.0)
                    else:
                        bucket = TokenBucket(
                            max_tokens=self._default_max,
                            refill_period=self._default_period,
                        )
                    self._buckets[tool_name] = bucket
        return self._buckets[tool_name]

    def check(self, tool_name: str) -> bool:
        """
        Check if a tool call is allowed under the rate limit.
        Returns True if allowed, False if rate-limited.
        """
        return self._get_bucket(tool_name).consume(1)

    def available(self, tool_name: str) -> float:
        """Return remaining tokens for a tool."""
        return self._get_bucket(tool_name).available


# Global singleton configured from environment
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Return the global RateLimiter singleton."""
    global _rate_limiter
    if _rate_limiter is None:
        max_tokens = int(os.getenv("WAZUH_RATE_LIMIT_TOKENS", "30"))
        refill_period = float(os.getenv("WAZUH_RATE_LIMIT_PERIOD", "60"))
        _rate_limiter = RateLimiter(max_tokens=max_tokens, refill_period=refill_period)
    return _rate_limiter
