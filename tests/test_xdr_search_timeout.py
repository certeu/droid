"""
Tests of the client timeout of a Microsoft XDR hunting query

Graph gives a single hunting query three minutes before timing it out, and a
heavy tenant really does take that long. A client that gives up sooner throws
away a query the service would have answered, then retries it four more times.
"""

from datetime import datetime, timedelta

import pytest

from droid.platforms import ms_xdr as xdr_module
from droid.platforms.ms_xdr import MicrosoftXDRPlatform

LOGGER_PARAM = {"debug_mode": False, "json_enabled": False}

RULE_FILE = "rules/sigma/delivery/anchovy_smuggling_on_neptune.yml"

TENANT = "tenant-planet-express"

XDR_PARAMETERS = {
    "query_period": "1h",
    "days_ago": 1,
    "tenant_id": TENANT,
    "search_auth": "default",
    "export_auth": "default",
}

# The documented server side limit, which the client must not undercut
GRAPH_HUNTING_QUERY_LIMIT = 180


class FakeResponse:
    status_code = 200

    @staticmethod
    def json():
        return {"results": []}


@pytest.fixture
def requests_recording_timeouts(monkeypatch):
    """Capture what every Graph call asks of requests, sending nothing"""

    calls = []

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append({"url": url, "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr(xdr_module.requests, "post", fake_post)

    return calls


@pytest.fixture
def platform():
    platform = MicrosoftXDRPlatform(XDR_PARAMETERS, LOGGER_PARAM)
    # A token that has not expired, so no call reaches the identity platform
    platform._token_cache[TENANT] = ("a-token", datetime.now() + timedelta(hours=1))
    return platform


def test_a_hunting_query_waits_out_the_graph_timeout(platform, requests_recording_timeouts):
    """Graph answers a heavy tenant in up to three minutes: the client must wait."""

    platform.run_xdr_search(
        "DeviceProcessEvents", RULE_FILE, tenant_id=TENANT, rule_content=None
    )

    hunting_call = requests_recording_timeouts[0]
    assert hunting_call["url"].endswith("/security/runHuntingQuery")
    assert hunting_call["timeout"] >= GRAPH_HUNTING_QUERY_LIMIT


def test_the_other_calls_keep_the_shorter_timeout(platform, requests_recording_timeouts):
    """Only hunting is slow. A rule creation hanging for three minutes is a fault."""

    platform._post(url="/security/rules/detectionRules", payload={}, tenant_id=TENANT)

    assert requests_recording_timeouts[0]["timeout"] < GRAPH_HUNTING_QUERY_LIMIT
