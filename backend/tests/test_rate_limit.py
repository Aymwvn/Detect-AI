"""Tests for app/core/rate_limit.py"""

from app.core.rate_limit import _RateLimiterState


def test_allows_requests_under_limit():
    state = _RateLimiterState(limit_per_minute=5)
    for _ in range(5):
        assert state.allow("client-1", now=0.0) is True


def test_blocks_requests_over_limit():
    state = _RateLimiterState(limit_per_minute=3)
    for _ in range(3):
        assert state.allow("client-1", now=0.0) is True
    assert state.allow("client-1", now=0.0) is False


def test_different_clients_have_independent_limits():
    state = _RateLimiterState(limit_per_minute=2)
    assert state.allow("client-1", now=0.0) is True
    assert state.allow("client-1", now=0.0) is True
    assert state.allow("client-1", now=0.0) is False
    # client-2 is unaffected by client-1's usage
    assert state.allow("client-2", now=0.0) is True
    assert state.allow("client-2", now=0.0) is True


def test_old_requests_fall_out_of_the_window():
    state = _RateLimiterState(limit_per_minute=2)
    assert state.allow("client-1", now=0.0) is True
    assert state.allow("client-1", now=0.0) is True
    assert state.allow("client-1", now=0.0) is False  # over limit at t=0

    # 61 seconds later, the first two requests have fallen out of the
    # 60-second sliding window
    assert state.allow("client-1", now=61.0) is True
