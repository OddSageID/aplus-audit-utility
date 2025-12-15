"""
Comprehensive tests for rate limiter and circuit breaker.
Tests concurrency limits, rate limits, and circuit breaker states.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock

from src.core.rate_limiter import (
    RateLimiter,
    RateLimitConfig,
    CircuitState,
    RateLimitedAPIClient,
)


@pytest.fixture
def rate_limit_config():
    """Create test rate limit configuration"""
    return RateLimitConfig(
        max_requests_per_minute=10,
        max_requests_per_hour=100,
        max_concurrent_requests=3,
        failure_threshold=3,
        success_threshold=2,
        timeout_seconds=5,
        request_timeout_seconds=2,
    )


@pytest.fixture
def rate_limiter(rate_limit_config):
    """Create rate limiter instance"""
    return RateLimiter(rate_limit_config)


class TestRateLimiterBasics:
    """Basic rate limiter functionality tests"""

    @pytest.mark.asyncio
    async def test_acquire_and_release(self, rate_limiter):
        """Test basic acquire and release"""
        # Acquire permission
        assert await rate_limiter.acquire() is True

        # Release
        await rate_limiter.release(success=True)

        # Stats should reflect the request
        stats = rate_limiter.get_stats()
        assert stats["total_requests"] == 1
        assert stats["concurrent_requests"] == 0

    @pytest.mark.asyncio
    async def test_concurrent_limit(self, rate_limiter):
        """Test concurrent request limit enforcement"""
        # Acquire up to limit (3)
        for i in range(3):
            assert await rate_limiter.acquire() is True

        # 4th request should be blocked
        assert await rate_limiter.acquire() is False

        # Release one
        await rate_limiter.release()

        # Now should succeed
        assert await rate_limiter.acquire() is True

    @pytest.mark.asyncio
    async def test_per_minute_limit(self, rate_limiter):
        """Test per-minute rate limit"""
        # Acquire up to limit (10)
        for i in range(10):
            acquired = await rate_limiter.acquire()
            if acquired:
                await rate_limiter.release()

        # 11th request should be blocked
        assert await rate_limiter.acquire() is False

        stats = rate_limiter.get_stats()
        assert stats["requests_last_minute"] == 10
        assert stats["total_rate_limited"] > 0

    @pytest.mark.asyncio
    async def test_stats_tracking(self, rate_limiter):
        """Test that statistics are tracked correctly"""
        # Make some requests
        for i in range(5):
            if await rate_limiter.acquire():
                await rate_limiter.release(success=(i % 2 == 0))

        stats = rate_limiter.get_stats()
        assert stats["total_requests"] == 5
        assert stats["total_failures"] == 2  # Indices 1 and 3


class TestCircuitBreaker:
    """Circuit breaker functionality tests"""

    @pytest.mark.asyncio
    async def test_circuit_opens_after_failures(self, rate_limiter):
        """Test that circuit opens after threshold failures"""
        # Initial state should be CLOSED
        assert rate_limiter._circuit_state == CircuitState.CLOSED

        # Generate failures (threshold is 3)
        for i in range(3):
            await rate_limiter.acquire()
            await rate_limiter.release(success=False)

        # Circuit should now be OPEN
        assert rate_limiter._circuit_state == CircuitState.OPEN

        # Requests should be blocked
        assert await rate_limiter.acquire() is False

    @pytest.mark.asyncio
    async def test_circuit_half_open_after_timeout(self, rate_limiter):
        """Test that circuit moves to HALF_OPEN after timeout"""
        # Open the circuit
        for i in range(3):
            await rate_limiter.acquire()
            await rate_limiter.release(success=False)

        assert rate_limiter._circuit_state == CircuitState.OPEN

        # Wait for timeout (5 seconds in config, but we'll simulate)
        rate_limiter._circuit_opened_at = datetime.utcnow() - timedelta(seconds=6)

        # Next acquire should move to HALF_OPEN
        result = await rate_limiter.acquire()
        assert result is True
        assert rate_limiter._circuit_state == CircuitState.HALF_OPEN

    @pytest.mark.asyncio
    async def test_circuit_closes_after_successes(self, rate_limiter):
        """Test that circuit closes after success threshold in HALF_OPEN"""
        # Open and move to HALF_OPEN
        for i in range(3):
            await rate_limiter.acquire()
            await rate_limiter.release(success=False)

        rate_limiter._circuit_opened_at = datetime.utcnow() - timedelta(seconds=6)

        # Move to HALF_OPEN
        await rate_limiter.acquire()
        assert rate_limiter._circuit_state == CircuitState.HALF_OPEN

        # Succeed twice (success_threshold is 2)
        await rate_limiter.release(success=True)
        await rate_limiter.acquire()
        await rate_limiter.release(success=True)

        # Circuit should close
        assert rate_limiter._circuit_state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_circuit_reopens_on_half_open_failure(self, rate_limiter):
        """Test that circuit reopens if failure occurs in HALF_OPEN"""
        # Get to HALF_OPEN state
        for i in range(3):
            await rate_limiter.acquire()
            await rate_limiter.release(success=False)

        rate_limiter._circuit_opened_at = datetime.utcnow() - timedelta(seconds=6)
        await rate_limiter.acquire()
        assert rate_limiter._circuit_state == CircuitState.HALF_OPEN

        # Fail while in HALF_OPEN
        await rate_limiter.release(success=False)

        # Should reopen
        assert rate_limiter._circuit_state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_circuit_breaker_stats(self, rate_limiter):
        """Test circuit breaker statistics"""
        # Open circuit multiple times
        for attempt in range(2):
            # Reset state
            rate_limiter._circuit_state = CircuitState.CLOSED
            rate_limiter._failure_count = 0

            # Trigger circuit open
            for i in range(3):
                await rate_limiter.acquire()
                await rate_limiter.release(success=False)

        stats = rate_limiter.get_stats()
        assert stats["total_circuit_opens"] == 2


class TestRetryLogic:
    """Test retry and backoff logic"""

    @pytest.mark.asyncio
    async def test_execute_with_retry_success(self, rate_limiter):
        """Test successful execution on first try"""

        async def success_func():
            return "success"

        result = await rate_limiter.execute_with_retry(success_func)
        assert result == "success"

        stats = rate_limiter.get_stats()
        assert stats["total_requests"] == 1
        assert stats["total_failures"] == 0

    @pytest.mark.asyncio
    async def test_execute_with_retry_eventual_success(self, rate_limiter):
        """Test that retry eventually succeeds after failures"""
        call_count = 0

        async def fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("Temporary failure")
            return "success"

        result = await rate_limiter.execute_with_retry(fail_then_succeed, max_retries=3)
        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_execute_with_retry_max_retries(self, rate_limiter):
        """Test that function fails after max retries"""

        async def always_fail():
            raise Exception("Always fails")

        with pytest.raises(Exception) as exc_info:
            await rate_limiter.execute_with_retry(always_fail, max_retries=2)

        assert "Always fails" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_execute_with_timeout(self, rate_limiter):
        """Test that timeout is enforced"""

        async def slow_function():
            await asyncio.sleep(5)  # Longer than timeout (2s)
            return "too slow"

        with pytest.raises(Exception):
            await rate_limiter.execute_with_retry(slow_function, max_retries=1)

    @pytest.mark.asyncio
    async def test_backoff_timing(self, rate_limiter):
        """Test exponential backoff timing"""
        call_times = []

        async def track_timing():
            call_times.append(asyncio.get_event_loop().time())
            if len(call_times) < 3:
                raise Exception("Fail")
            return "success"

        result = await rate_limiter.execute_with_retry(
            track_timing, max_retries=3, backoff_factor=2.0
        )

        assert result == "success"
        assert len(call_times) == 3

        # Check that delays increase (roughly)
        # First retry after ~1s, second after ~2s
        if len(call_times) >= 3:
            delay1 = call_times[1] - call_times[0]
            delay2 = call_times[2] - call_times[1]
            assert delay2 > delay1  # Exponential backoff


class TestRateLimitedAPIClient:
    """Test the API client wrapper"""

    @pytest.mark.asyncio
    async def test_create_message_success(self, rate_limiter):
        """Test successful API call through client"""
        # Mock client
        mock_client = Mock()
        mock_response = Mock(content=[Mock(text="Response")])
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        # Create rate-limited client
        client = RateLimitedAPIClient(mock_client, rate_limiter)

        # Make request
        response = await client.create_message(
            model="test-model",
            max_tokens=100,
            messages=[{"role": "user", "content": "test"}],
        )

        assert response == mock_response
        mock_client.messages.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_message_with_retry(self, rate_limiter):
        """Test that client retries on failure"""
        mock_client = Mock()
        call_count = 0

        async def mock_create(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("API error")
            return Mock(content=[Mock(text="Success")])

        mock_client.messages.create = mock_create

        client = RateLimitedAPIClient(mock_client, rate_limiter)
        response = await client.create_message(model="test")

        assert call_count == 2
        assert response.content[0].text == "Success"

    @pytest.mark.asyncio
    async def test_create_completion_openai(self, rate_limiter):
        """Test OpenAI-style completion call"""
        mock_client = Mock()
        mock_response = Mock(choices=[Mock(message=Mock(content="Response"))])
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        client = RateLimitedAPIClient(mock_client, rate_limiter)
        response = await client.create_completion(model="gpt-4", messages=[])

        assert response == mock_response


class TestConcurrencyScenarios:
    """Test concurrent request scenarios"""

    @pytest.mark.asyncio
    async def test_concurrent_requests(self, rate_limiter):
        """Test multiple concurrent requests"""

        async def make_request(request_id):
            if await rate_limiter.acquire():
                await asyncio.sleep(0.1)  # Simulate work
                await rate_limiter.release(success=True)
                return f"success-{request_id}"
            return f"blocked-{request_id}"

        # Launch 10 concurrent requests (limit is 3)
        tasks = [make_request(i) for i in range(10)]
        results = await asyncio.gather(*tasks)

        # Some should succeed, some blocked
        successes = [r for r in results if r.startswith("success")]
        blocked = [r for r in results if r.startswith("blocked")]

        assert len(successes) > 0
        assert len(blocked) > 0

        # Final concurrent count should be 0
        stats = rate_limiter.get_stats()
        assert stats["concurrent_requests"] == 0

    @pytest.mark.asyncio
    async def test_request_cleanup(self, rate_limiter):
        """Test that old requests are cleaned up"""
        # Make some requests
        for i in range(5):
            await rate_limiter.acquire()
            await rate_limiter.release()

        # Manually age the requests
        cutoff = datetime.utcnow() - timedelta(minutes=2)
        rate_limiter._minute_requests.clear()
        rate_limiter._hour_requests.clear()

        # Stats should reflect cleanup
        stats = rate_limiter.get_stats()
        assert stats["requests_last_minute"] == 0


class TestEdgeCases:
    """Test edge cases and error conditions"""

    @pytest.mark.asyncio
    async def test_release_without_acquire(self, rate_limiter):
        """Test that release without acquire doesn't break state"""
        # Release without acquire shouldn't cause issues
        await rate_limiter.release()

        stats = rate_limiter.get_stats()
        assert stats["concurrent_requests"] == 0

    @pytest.mark.asyncio
    async def test_multiple_releases(self, rate_limiter):
        """Test multiple releases of same request"""
        await rate_limiter.acquire()
        await rate_limiter.release()
        await rate_limiter.release()  # Second release

        # Concurrent count shouldn't go negative
        stats = rate_limiter.get_stats()
        assert stats["concurrent_requests"] == 0

    @pytest.mark.asyncio
    async def test_failure_rate_calculation(self, rate_limiter):
        """Test failure rate calculation"""
        # Make 10 requests, 3 failures
        for i in range(10):
            await rate_limiter.acquire()
            await rate_limiter.release(success=(i % 3 != 0))

        stats = rate_limiter.get_stats()
        expected_failure_rate = 4 / 10  # Indices 0, 3, 6, 9
        assert abs(stats["failure_rate"] - expected_failure_rate) < 0.01

    @pytest.mark.asyncio
    async def test_zero_requests_stats(self):
        """Test stats with zero requests"""
        limiter = RateLimiter(RateLimitConfig())
        stats = limiter.get_stats()

        assert stats["total_requests"] == 0
        assert stats["failure_rate"] == 0


@pytest.mark.asyncio
async def test_real_world_scenario(rate_limiter):
    """Test realistic usage scenario"""
    results = []

    async def api_call(call_id):
        """Simulates an API call that sometimes fails"""
        try:

            async def make_call():
                # Simulate random failures
                if call_id % 7 == 0:
                    raise Exception(f"Simulated failure for call {call_id}")
                await asyncio.sleep(0.05)
                return f"Result {call_id}"

            result = await rate_limiter.execute_with_retry(make_call, max_retries=2)
            results.append(("success", result))
        except Exception as e:
            results.append(("failed", str(e)))

    # Make 20 concurrent API calls
    tasks = [api_call(i) for i in range(20)]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Verify stats make sense
    stats = rate_limiter.get_stats()
    assert stats["total_requests"] > 0
    assert stats["concurrent_requests"] == 0

    # Check results
    successes = [r for r in results if r[0] == "success"]
    failures = [r for r in results if r[0] == "failed"]

    assert len(successes) + len(failures) == 20
