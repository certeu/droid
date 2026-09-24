"""
Tests of the Microsoft Graph throttling behaviour
"""

from datetime import datetime, timedelta, timezone

import pytest

from droid.platforms import ms_xdr


class FakeLogger:
    def __init__(self):
        self.warnings = []
        self.errors = []

    def debug(self, message, *args, **kwargs):
        pass

    def warning(self, message, *args, **kwargs):
        self.warnings.append(message)

    def error(self, message, *args, **kwargs):
        self.errors.append(message)


class FakeResponse:
    def __init__(self, status_code, headers=None, body=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body if body is not None else {}

    def json(self):
        return self._body


class FakeXdrPlatform:
    """Minimal stand-in exposing only what _request_with_retries uses"""

    _parse_retry_after = ms_xdr.MicrosoftXDRPlatform._parse_retry_after
    _request_with_retries = ms_xdr.MicrosoftXDRPlatform._request_with_retries

    def __init__(self):
        self.logger = FakeLogger()
        self._api_base_url = "https://graph.microsoft.com/beta"
        self._tenant_id = "a-tenant"
        # a token valid far enough in the future to skip any refresh
        self._token_cache = {"a-tenant": ("a-token", datetime.now() + timedelta(hours=1))}


@pytest.fixture
def platform():
    return FakeXdrPlatform()


@pytest.fixture
def sleeps(monkeypatch):
    """Capture the delays instead of actually waiting for them"""
    recorded = []
    monkeypatch.setattr(ms_xdr.time, "sleep", lambda seconds: recorded.append(seconds))
    return recorded


def queue_responses(monkeypatch, responses):
    """Serve the given responses one by one to requests.post"""
    remaining = list(responses)

    def fake_post(*args, **kwargs):
        return remaining.pop(0)

    monkeypatch.setattr(ms_xdr.requests, "post", fake_post)
    return remaining


def test_retry_after_seconds_is_honoured(platform, sleeps, monkeypatch):
    queue_responses(
        monkeypatch,
        [
            FakeResponse(429, {"Retry-After": "10"}),
            FakeResponse(200, body={"results": []}),
        ],
    )

    body, status = platform._request_with_retries("POST", url="/security/runHuntingQuery")

    assert (body, status) == ({"results": []}, 200)
    assert sleeps == [10.0]


def test_retry_after_http_date_is_honoured(platform, sleeps, monkeypatch):
    retry_date = datetime.now(timezone.utc) + timedelta(seconds=20)
    header = retry_date.strftime("%a, %d %b %Y %H:%M:%S GMT")
    queue_responses(
        monkeypatch,
        [FakeResponse(429, {"Retry-After": header}), FakeResponse(200)],
    )

    platform._request_with_retries("POST", url="/security/runHuntingQuery")

    assert len(sleeps) == 1
    assert 15 <= sleeps[0] <= 20


def test_retry_after_is_capped(platform, sleeps, monkeypatch):
    queue_responses(
        monkeypatch,
        [FakeResponse(429, {"Retry-After": "99999"}), FakeResponse(200)],
    )

    platform._request_with_retries("POST", url="/security/runHuntingQuery")

    assert sleeps == [ms_xdr.MAX_RETRY_AFTER_SECONDS]


def test_unparsable_retry_after_falls_back_to_backoff(platform, sleeps, monkeypatch):
    queue_responses(
        monkeypatch,
        [FakeResponse(429, {"Retry-After": "soon"}), FakeResponse(200)],
    )

    platform._request_with_retries("POST", url="/security/runHuntingQuery", retry_delay=30)

    assert sleeps == [30]


def test_missing_retry_after_backs_off_exponentially(platform, sleeps, monkeypatch):
    queue_responses(
        monkeypatch,
        [FakeResponse(429), FakeResponse(429), FakeResponse(429), FakeResponse(200)],
    )

    platform._request_with_retries("POST", url="/security/runHuntingQuery", retry_delay=30)

    assert sleeps == [30, 60, 120]


def test_throttling_does_not_consume_the_regular_retry_budget(platform, sleeps, monkeypatch):
    """A long burst of 429s used to exhaust max_retries and abort the query"""
    queue_responses(
        monkeypatch,
        [FakeResponse(429, {"Retry-After": "1"})] * 8 + [FakeResponse(200, body={"ok": True})],
    )

    body, status = platform._request_with_retries(
        "POST", url="/security/runHuntingQuery", max_retries=5
    )

    assert (body, status) == ({"ok": True}, 200)
    assert sleeps == [1.0] * 8


def test_persistent_throttling_eventually_gives_up(platform, sleeps, monkeypatch):
    queue_responses(monkeypatch, [FakeResponse(429, {"Retry-After": "1"})] * 10)

    with pytest.raises(Exception, match="throttled after 3 retries"):
        platform._request_with_retries(
            "POST", url="/security/runHuntingQuery", max_throttle_retries=3
        )

    assert sleeps == [1.0] * 3


def test_server_error_honours_retry_after(platform, sleeps, monkeypatch):
    queue_responses(
        monkeypatch,
        [FakeResponse(503, {"Retry-After": "5"}), FakeResponse(200)],
    )

    platform._request_with_retries("POST", url="/security/runHuntingQuery", retry_delay=60)

    assert sleeps == [5.0]
