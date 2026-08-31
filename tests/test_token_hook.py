"""
Tests of the Azure token hook behaviour
"""

import pytest

from droid.platforms import ms_xdr, sentinel

TOKEN_HOOK_ENV_VARS = (
    "DROID_AZURE_TOKEN_X_API_KEY",
    "DROID_AZURE_TOKEN_HEADER",
    "DROID_AZURE_TOKEN_HEADER_VALUE",
)


class FakeLogger:
    def debug(self, message, *args, **kwargs):
        pass

    def error(self, message, *args, **kwargs):
        pass


class FakeResponse:
    status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return {"access_token": "a-token"}


class FakeSentinelPlatform:
    """Minimal stand-in exposing only what _acquire_token_from_hook uses"""

    _acquire_token_from_hook = sentinel.SentinelPlatform._acquire_token_from_hook

    def __init__(self):
        self.logger = FakeLogger()
        self._tenant_id = "a-tenant"
        self._token = None
        self._token_expiration = None
        self._current_scope = None


class FakeXdrPlatform:
    """Minimal stand-in exposing only what _acquire_token_from_hook uses"""

    _acquire_token_from_hook = ms_xdr.MicrosoftXDRPlatform._acquire_token_from_hook

    def __init__(self):
        self.logger = FakeLogger()
        self._tenant_id = "a-tenant"
        self._token_cache = {}


@pytest.fixture(autouse=True)
def clean_token_hook_env(monkeypatch):
    """Make sure the tests are not influenced by the environment"""
    for name in TOKEN_HOOK_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def recorded_requests(monkeypatch):
    """Capture the calls made to requests.get by both platform modules"""
    calls = []

    def fake_get(url, **kwargs):
        calls.append({"url": url, **kwargs})
        return FakeResponse()

    monkeypatch.setattr(sentinel.requests, "get", fake_get)
    monkeypatch.setattr(ms_xdr.requests, "get", fake_get)

    return calls


def test_sentinel_token_hook_sends_api_key_header(monkeypatch, recorded_requests):
    monkeypatch.setenv("DROID_AZURE_TOKEN_X_API_KEY", "secret")

    token, _ = FakeSentinelPlatform()._acquire_token_from_hook(
        "https://hook.example/token", "management.azure.com"
    )

    assert token == "a-token"
    assert recorded_requests[0]["headers"] == {"X-API-Key": "secret"}


def test_sentinel_token_hook_sends_custom_header(monkeypatch, recorded_requests):
    monkeypatch.setenv("DROID_AZURE_TOKEN_X_API_KEY", "secret")
    monkeypatch.setenv("DROID_AZURE_TOKEN_HEADER", "foo")
    monkeypatch.setenv("DROID_AZURE_TOKEN_HEADER_VALUE", "bar")

    token, _ = FakeSentinelPlatform()._acquire_token_from_hook(
        "https://hook.example/token", "management.azure.com"
    )

    assert token == "a-token"
    assert recorded_requests[0]["headers"] == {"foo": "bar"}


def test_sentinel_token_hook_sends_no_header_by_default(recorded_requests):
    FakeSentinelPlatform()._acquire_token_from_hook(
        "https://hook.example/token", "management.azure.com"
    )

    assert recorded_requests[0]["headers"] == {}


def test_sentinel_token_hook_fails_on_incomplete_custom_header(monkeypatch, recorded_requests):
    monkeypatch.setenv("DROID_AZURE_TOKEN_HEADER", "foo")

    with pytest.raises(ValueError, match="DROID_AZURE_TOKEN_HEADER_VALUE"):
        FakeSentinelPlatform()._acquire_token_from_hook(
            "https://hook.example/token", "management.azure.com"
        )

    assert recorded_requests == []


def test_xdr_token_hook_sends_api_key_header(monkeypatch, recorded_requests):
    monkeypatch.setenv("DROID_AZURE_TOKEN_X_API_KEY", "secret")

    token, _ = FakeXdrPlatform()._acquire_token_from_hook("https://hook.example/token")

    assert token == "a-token"
    assert recorded_requests[0]["headers"] == {"X-API-Key": "secret"}


def test_xdr_token_hook_sends_custom_header(monkeypatch, recorded_requests):
    monkeypatch.setenv("DROID_AZURE_TOKEN_X_API_KEY", "secret")
    monkeypatch.setenv("DROID_AZURE_TOKEN_HEADER", "foo")
    monkeypatch.setenv("DROID_AZURE_TOKEN_HEADER_VALUE", "bar")

    token, _ = FakeXdrPlatform()._acquire_token_from_hook("https://hook.example/token")

    assert token == "a-token"
    assert recorded_requests[0]["headers"] == {"foo": "bar"}


def test_xdr_token_hook_sends_no_header_by_default(recorded_requests):
    FakeXdrPlatform()._acquire_token_from_hook("https://hook.example/token")

    assert recorded_requests[0]["headers"] == {}


def test_xdr_token_hook_fails_on_incomplete_custom_header(monkeypatch, recorded_requests):
    monkeypatch.setenv("DROID_AZURE_TOKEN_HEADER_VALUE", "bar")

    with pytest.raises(ValueError, match="DROID_AZURE_TOKEN_HEADER"):
        FakeXdrPlatform()._acquire_token_from_hook("https://hook.example/token")

    assert recorded_requests == []
