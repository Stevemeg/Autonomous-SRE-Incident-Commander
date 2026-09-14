"""Non-vacuous rate limiting at the authenticated principal boundary."""

from asic.api.rate_limit import RateLimiter


def test_rate_limit_guard_is_causal() -> None:
    now = [10.0]
    limiter = RateLimiter(2, window_seconds=60, clock=lambda: now[0])
    assert limiter.admit("tenant:user")
    assert limiter.admit("tenant:user")
    assert not limiter.admit("tenant:user")
    assert limiter.admit("tenant:other-user")
    now[0] = 71.0
    assert limiter.admit("tenant:user")
