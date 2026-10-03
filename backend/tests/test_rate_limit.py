"""Unit tests for the in-memory sliding-window rate limiter."""

import time

from utils.rate_limit import RateLimiter


def test_allows_up_to_max_attempts():
    limiter = RateLimiter(max_attempts=3, window_seconds=60)
    key = "1.2.3.4"
    for _ in range(3):
        assert limiter.is_allowed(key) is True
        limiter.record_attempt(key)
    assert limiter.is_allowed(key) is False


def test_different_keys_are_independent():
    limiter = RateLimiter(max_attempts=1, window_seconds=60)
    limiter.record_attempt("1.1.1.1")
    assert limiter.is_allowed("1.1.1.1") is False
    assert limiter.is_allowed("2.2.2.2") is True


def test_attempts_expire_after_the_window():
    limiter = RateLimiter(max_attempts=1, window_seconds=0.05)
    key = "1.2.3.4"
    limiter.record_attempt(key)
    assert limiter.is_allowed(key) is False
    time.sleep(0.1)
    assert limiter.is_allowed(key) is True
