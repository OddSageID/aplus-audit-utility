"""
Rate limiting and circuit breaker for AI API calls.
Prevents API abuse and handles transient failures gracefully.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Callable, Any
from enum import Enum
import asyncio
import logging
from collections import deque
import inspect


class CircuitState(Enum):
    """Circuit breaker states"""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing - reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""

    max_requests_per_minute: int = 60
    max_requests_per_hour: int = 1000
    max_concurrent_requests: int = 5

    # Circuit breaker settings
    failure_threshold: int = 5  # failures before opening circuit
    success_threshold: int = 2  # successes to close circuit from half-open
    timeout_seconds: int = 60  # how long circuit stays open

    # Request timeout
    request_timeout_seconds: int = 30


class RateLimiter:
    """
    Token bucket rate limiter with circuit breaker.
    Thread-safe implementation for async operations.
    """

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Rate limiting state
        self._minute_requests: deque = deque()
        self._hour_requests: deque = deque()
        self._concurrent_count: int = 0
        self._lock = None

        # Circuit breaker state
        self._circuit_state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._circuit_opened_at: Optional[datetime] = None

        # Metrics
        self.total_requests = 0
        self.total_failures = 0
        self.total_rate_limited = 0
        self.total_circuit_opens = 0

    async def acquire(self) -> bool:
        """
        Attempt to acquire permission for API request.

        Returns:
            True if request allowed, False if rate limited
        """
        if self._lock is None:
            self._lock = asyncio.Lock()

        async with self._lock:
            now = datetime.utcnow()

            # Check circuit breaker first
            if not await self._check_circuit(now):
                self.logger.warning("Request blocked: Circuit breaker is OPEN")
                return False

            # Clean old requests
            self._cleanup_old_requests(now)

            # Check concurrent limit
            if self._concurrent_count >= self.config.max_concurrent_requests:
                self.total_rate_limited += 1
                self.logger.warning(
                    f"Request blocked: Concurrent limit ({self.config.max_concurrent_requests})"
                )
                return False

            # Check per-minute limit
            if len(self._minute_requests) >= self.config.max_requests_per_minute:
                self.total_rate_limited += 1
                self.logger.warning(
                    f"Request blocked: Per-minute limit ({self.config.max_requests_per_minute})"
                )
                return False

            # Check per-hour limit
            if len(self._hour_requests) >= self.config.max_requests_per_hour:
                self.total_rate_limited += 1
                self.logger.warning(
                    f"Request blocked: Per-hour limit ({self.config.max_requests_per_hour})"
                )
                return False

            # Grant access
            self._minute_requests.append(now)
            self._hour_requests.append(now)
            self._concurrent_count += 1
            self.total_requests += 1

            return True

    async def release(self, success: bool = True):
        """
        Release concurrent slot and update circuit breaker.

        Args:
            success: Whether the request succeeded
        """
        if self._lock is None:
            self._lock = asyncio.Lock()

        async with self._lock:
            had_request = self._concurrent_count > 0
            if had_request:
                self._concurrent_count = max(0, self._concurrent_count - 1)

            # Only record outcomes when a request was actually in flight
            if not had_request:
                return

            if success:
                await self._record_success()
            else:
                await self._record_failure()

    async def _check_circuit(self, now: datetime) -> bool:
        """Check if circuit breaker allows requests"""
        if self._circuit_state == CircuitState.CLOSED:
            return True

        if self._circuit_state == CircuitState.OPEN:
            # Check if timeout expired
            if self._circuit_opened_at:
                elapsed = (now - self._circuit_opened_at).total_seconds()
                if elapsed >= self.config.timeout_seconds:
                    # Move to half-open state
                    self._circuit_state = CircuitState.HALF_OPEN
                    self._success_count = 0
                    self.logger.info("Circuit breaker: OPEN -> HALF_OPEN")
                    return True
            return False

        # HALF_OPEN state - allow limited requests
        return True

    async def _record_success(self):
        """Record successful request"""
        if self._circuit_state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.config.success_threshold:
                # Close circuit
                self._circuit_state = CircuitState.CLOSED
                self._failure_count = 0
                self._success_count = 0
                self.logger.info("Circuit breaker: HALF_OPEN -> CLOSED")
        else:
            # Reset failure streak on normal successes
            if self._failure_count > 0:
                self._failure_count = 0

    async def _record_failure(self):
        """Record failed request and update circuit breaker"""
        self.total_failures += 1

        if self._circuit_state == CircuitState.HALF_OPEN:
            # Failure in half-open state - reopen circuit
            self._circuit_state = CircuitState.OPEN
            self._circuit_opened_at = datetime.utcnow()
            self.total_circuit_opens += 1
            self.logger.warning("Circuit breaker: HALF_OPEN -> OPEN (failure detected)")
            return

        if self._circuit_state == CircuitState.CLOSED:
            self._failure_count += 1
            if self._failure_count >= self.config.failure_threshold:
                # Open circuit
                self._circuit_state = CircuitState.OPEN
                self._circuit_opened_at = datetime.utcnow()
                self.total_circuit_opens += 1
                self.logger.error(
                    f"Circuit breaker: CLOSED -> OPEN "
                    f"({self._failure_count} consecutive failures)"
                )

    def _cleanup_old_requests(self, now: datetime):
        """Remove expired request timestamps"""
        minute_cutoff = now - timedelta(minutes=1)
        hour_cutoff = now - timedelta(hours=1)

        # Clean minute bucket
        while self._minute_requests and self._minute_requests[0] < minute_cutoff:
            self._minute_requests.popleft()

        # Clean hour bucket
        while self._hour_requests and self._hour_requests[0] < hour_cutoff:
            self._hour_requests.popleft()

    def get_stats(self) -> dict:
        """Get rate limiter statistics"""
        return {
            "circuit_state": self._circuit_state.value,
            "concurrent_requests": self._concurrent_count,
            "requests_last_minute": len(self._minute_requests),
            "requests_last_hour": len(self._hour_requests),
            "total_requests": self.total_requests,
            "total_failures": self.total_failures,
            "total_rate_limited": self.total_rate_limited,
            "total_circuit_opens": self.total_circuit_opens,
            "failure_rate": (
                self.total_failures / self.total_requests if self.total_requests > 0 else 0
            ),
        }

    async def execute_with_retry(
        self,
        func: Callable,
        *args,
        max_retries: int = 3,
        backoff_factor: float = 1.5,
        **kwargs,
    ) -> Any:
        """
        Execute function with automatic retry and rate limiting.

        Args:
            func: Async function to execute
            *args: Positional arguments for func
            max_retries: Maximum retry attempts
            backoff_factor: Exponential backoff multiplier
            **kwargs: Keyword arguments for func

        Returns:
            Result from func

        Raises:
            Exception: If all retries fail
        """
        last_exception = None
        wait_time = 1.0

        for attempt in range(max_retries + 1):
            # Acquire rate limit permission
            if not await self.acquire():
                # Rate limited - wait and retry
                await asyncio.sleep(wait_time)
                wait_time *= backoff_factor
                continue

            try:
                # Execute function with timeout
                result = await asyncio.wait_for(
                    func(*args, **kwargs), timeout=self.config.request_timeout_seconds
                )

                # Success - release with success=True
                await self.release(success=True)
                return result

            except asyncio.TimeoutError as e:
                last_exception = e
                self.logger.warning(f"Request timeout (attempt {attempt + 1}/{max_retries + 1})")
                await self.release(success=False)

            except Exception as e:
                last_exception = e
                self.logger.warning(
                    f"Request failed (attempt {attempt + 1}/{max_retries + 1}): {str(e)}"
                )
                await self.release(success=False)

            # Wait before retry
            if attempt < max_retries:
                await asyncio.sleep(wait_time)
                wait_time *= backoff_factor

        # All retries failed
        raise last_exception or Exception("Request failed after all retries")


class RateLimitedAPIClient:
    """
    Wrapper for AI API clients with built-in rate limiting.
    Use this to wrap Anthropic/OpenAI clients.
    """

    def __init__(self, client: Any, rate_limiter: RateLimiter):
        self.client = client
        self.rate_limiter = rate_limiter
        self.logger = logging.getLogger(__name__)

    async def create_message(self, **kwargs) -> Any:
        """
        Create message with rate limiting and retry logic.

        Args:
            **kwargs: Arguments to pass to underlying client

        Returns:
            API response
        """

        async def _create():
            result = self.client.messages.create(**kwargs)
            if inspect.isawaitable(result):
                return await result
            return result

        return await self.rate_limiter.execute_with_retry(_create)

    async def create_completion(self, **kwargs) -> Any:
        """
        Create completion with rate limiting (for OpenAI).

        Args:
            **kwargs: Arguments to pass to underlying client

        Returns:
            API response
        """

        async def _create():
            result = self.client.chat.completions.create(**kwargs)
            if inspect.isawaitable(result):
                return await result
            return result

        return await self.rate_limiter.execute_with_retry(_create)
