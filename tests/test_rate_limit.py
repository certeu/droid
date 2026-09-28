"""
Tests of the Microsoft Graph throttling behaviour
"""

from datetime import datetime, timedelta, timezone

import pytest

from droid.platforms import ms_xdr


class FakeLogger:
    def __init__(self):
        self.debugs = []
        self.warnings = []
        self.errors = []

    def debug(self, message, *args, **kwargs):
        self.debugs.append(message)

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
    _throttling_details = ms_xdr.MicrosoftXDRPlatform._throttling_details
    _wait_out_throttling = ms_xdr.MicrosoftXDRPlatform._wait_out_throttling
    _request_with_retries = ms_xdr.MicrosoftXDRPlatform._request_with_retries

    def __init__(self):
        self.logger = FakeLogger()
        self._api_base_url = "https://graph.microsoft.com/beta"
        self._tenant_id = "a-tenant"
        self._max_throttle_wait = ms_xdr.DEFAULT_MAX_THROTTLE_WAIT
        self._throttled_until = {}
        # a token valid far enough in the future to skip any refresh
        self._token_cache = {"a-tenant": ("a-token", datetime.now() + timedelta(hours=1))}


@pytest.fixture
def platform():
    return FakeXdrPlatform()


@pytest.fixture
def sleeps(monkeypatch):
    """Capture the delays instead of waiting, advancing a fake clock by each one"""
    recorded = []
    clock = {"now": 1000.0}

    def fake_sleep(seconds):
        recorded.append(seconds)
        clock["now"] += seconds

    monkeypatch.setattr(ms_xdr.time, "sleep", fake_sleep)
    monkeypatch.setattr(ms_xdr.time, "monotonic", lambda: clock["now"])
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


def test_long_retry_after_is_honoured_in_full(platform, sleeps, monkeypatch):
    """CpuQuotaExceeded asks for minutes; waiting less just earns another 429"""
    queue_responses(
        monkeypatch,
        [FakeResponse(429, {"Retry-After": "733"}), FakeResponse(200, body={"ok": True})],
    )

    body, status = platform._request_with_retries("POST", url="/security/runHuntingQuery")

    assert (body, status) == ({"ok": True}, 200)
    assert sleeps == [733.0]


def test_implausible_retry_after_is_capped_loudly(platform, sleeps, monkeypatch):
    queue_responses(
        monkeypatch,
        [FakeResponse(429, {"Retry-After": "99999"}), FakeResponse(200)],
    )

    platform._request_with_retries(
        "POST", url="/security/runHuntingQuery", max_throttle_wait=7200
    )

    assert sleeps == [float(ms_xdr.MAX_RETRY_AFTER_SECONDS)]
    assert any("implausibly long" in message for message in platform.logger.warnings)


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


def test_repeated_long_waits_stop_at_the_budget(platform, sleeps, monkeypatch):
    queue_responses(monkeypatch, [FakeResponse(429, {"Retry-After": "733"})] * 4)

    with pytest.raises(Exception, match="wait budget"):
        platform._request_with_retries(
            "POST", url="/security/runHuntingQuery", max_throttle_wait=1800
        )

    # two waits fit in the budget, the third would overrun it
    assert sleeps == [733.0, 733.0]


def test_unaffordable_wait_fails_fast_without_sleeping(platform, sleeps, monkeypatch):
    """Sleeping past the budget only to fail anyway would waste the whole wait"""
    queue_responses(monkeypatch, [FakeResponse(429, {"Retry-After": "733"})])

    with pytest.raises(Exception, match="wait budget"):
        platform._request_with_retries(
            "POST", url="/security/runHuntingQuery", max_throttle_wait=600
        )

    assert sleeps == []
    assert any("733 more seconds" in message for message in platform.logger.errors)


def test_throttle_wait_budget_comes_from_the_platform_parameters(monkeypatch, sleeps):
    configured = FakeXdrPlatform()
    configured._max_throttle_wait = 100
    queue_responses(monkeypatch, [FakeResponse(429, {"Retry-After": "733"})])

    with pytest.raises(Exception, match="beyond the 100s wait budget"):
        configured._request_with_retries("POST", url="/security/runHuntingQuery")

    assert sleeps == []


def counting_responses(monkeypatch, responses):
    """Serve the given responses, recording how many requests were actually sent"""
    remaining = list(responses)
    sent = []

    def fake_post(*args, **kwargs):
        sent.append(1)
        return remaining.pop(0)

    monkeypatch.setattr(ms_xdr.requests, "post", fake_post)
    return sent


def test_an_open_window_is_waited_out_by_the_next_request(platform, sleeps, monkeypatch):
    """A tenant-wide quota must not be rediscovered with a fresh 429 per rule"""
    sent = counting_responses(
        monkeypatch,
        [FakeResponse(429, {"Retry-After": "600"}), FakeResponse(200, body={"results": []})],
    )

    # the first rule learns the window but cannot afford it
    with pytest.raises(Exception, match="wait budget"):
        platform._request_with_retries(
            "POST", url="/security/runHuntingQuery", max_throttle_wait=60
        )
    assert len(sent) == 1

    # the next rule waits the window out rather than spending another 429 on it
    body, status = platform._request_with_retries(
        "POST", url="/security/runHuntingQuery", max_throttle_wait=3600
    )

    assert (body, status) == ({"results": []}, 200)
    assert len(sent) == 2
    assert sleeps == [600.0]
    assert sum("throttled for another" in message for message in platform.logger.warnings) == 1


def test_an_unaffordable_window_blocks_without_calling_graph(platform, sleeps, monkeypatch):
    """Rules that cannot outlast the window must not keep hitting the quota"""
    sent = counting_responses(monkeypatch, [FakeResponse(429, {"Retry-After": "600"})])

    for _ in range(3):
        with pytest.raises(Exception, match="wait budget"):
            platform._request_with_retries(
                "POST", url="/security/runHuntingQuery", max_throttle_wait=60
            )

    # only the first rule reached Graph; the rest were refused by the gate
    assert len(sent) == 1
    assert sleeps == []


def test_the_window_is_tracked_per_tenant(platform, sleeps, monkeypatch):
    """One customer being throttled must not stall the others in an MSSP run"""
    sent = counting_responses(
        monkeypatch,
        [FakeResponse(429, {"Retry-After": "600"}), FakeResponse(200, body={"results": []})],
    )
    platform._token_cache["other-tenant"] = ("a-token", datetime.now() + timedelta(hours=1))

    with pytest.raises(Exception, match="wait budget"):
        platform._request_with_retries(
            "POST", url="/security/runHuntingQuery", tenant_id="a-tenant", max_throttle_wait=60
        )

    body, status = platform._request_with_retries(
        "POST", url="/security/runHuntingQuery", tenant_id="other-tenant"
    )

    assert status == 200
    assert sleeps == []
    assert len(sent) == 2


def test_an_expired_window_is_forgotten(platform, sleeps, monkeypatch):
    sent = counting_responses(
        monkeypatch,
        [FakeResponse(429, {"Retry-After": "600"}), FakeResponse(200), FakeResponse(200)],
    )

    platform._request_with_retries("POST", url="/security/runHuntingQuery")
    assert sleeps == [600.0]

    # the window has been served, so the next request goes straight out
    platform._request_with_retries("POST", url="/security/runHuntingQuery")

    assert sleeps == [600.0]
    assert len(sent) == 3


def test_debug_reports_the_throttling_reason(platform, sleeps, monkeypatch):
    """The sample throttled response from the Graph throttling documentation"""
    throttled = FakeResponse(
        429,
        {"Retry-After": "10", "RateLimit-Remaining": "0", "x-ms-resource-unit": "5"},
        {
            "error": {
                "code": "TooManyRequests",
                "message": "Please retry again later.",
                "innerError": {
                    "code": "429",
                    "date": "2020-08-18T12:51:51",
                    "message": "Please retry after",
                    "request-id": "94fb3b52-452a-4535-a601-69e0a90e3aa2",
                    "status": "429",
                },
            }
        },
    )
    queue_responses(monkeypatch, [throttled, FakeResponse(200)])

    platform._request_with_retries("POST", url="/security/runHuntingQuery")

    reason = next(message for message in platform.logger.debugs if "Throttled on" in message)
    assert "code=TooManyRequests" in reason
    assert "message=Please retry again later." in reason
    assert "request-id=94fb3b52-452a-4535-a601-69e0a90e3aa2" in reason
    assert "Retry-After=10" in reason
    assert "RateLimit-Remaining=0" in reason
    assert "x-ms-resource-unit=5" in reason


def test_throttling_reason_survives_a_non_json_body(platform, sleeps, monkeypatch):
    """A gateway can answer 429 with HTML, which must not mask the throttling"""

    class HtmlResponse(FakeResponse):
        def json(self):
            raise ValueError("not JSON")

    queue_responses(
        monkeypatch,
        [HtmlResponse(429, {"Retry-After": "10"}), FakeResponse(200)],
    )

    platform._request_with_retries("POST", url="/security/runHuntingQuery")

    reason = next(message for message in platform.logger.debugs if "Throttled on" in message)
    assert "Retry-After=10" in reason
    assert sleeps == [10.0]


def test_throttling_reason_when_graph_says_nothing(platform, sleeps, monkeypatch):
    queue_responses(monkeypatch, [FakeResponse(429), FakeResponse(200)])

    platform._request_with_retries("POST", url="/security/runHuntingQuery")

    reason = next(message for message in platform.logger.debugs if "Throttled on" in message)
    assert "no details returned by Graph" in reason


def test_throttling_reason_is_logged_before_giving_up(platform, sleeps, monkeypatch):
    queue_responses(monkeypatch, [FakeResponse(429, {"Retry-After": "1"})] * 3)

    with pytest.raises(Exception, match="throttled after 2 retries"):
        platform._request_with_retries(
            "POST", url="/security/runHuntingQuery", max_throttle_retries=2
        )

    assert len([m for m in platform.logger.debugs if "Throttled on" in m]) == 3


def test_server_error_honours_retry_after(platform, sleeps, monkeypatch):
    queue_responses(
        monkeypatch,
        [FakeResponse(503, {"Retry-After": "5"}), FakeResponse(200)],
    )

    platform._request_with_retries("POST", url="/security/runHuntingQuery", retry_delay=60)

    assert sleeps == [5.0]
