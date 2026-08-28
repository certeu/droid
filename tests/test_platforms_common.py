"""
Tests of the common platform functions
"""

import pytest

from droid.platforms.common import get_token_hook_headers

TOKEN_HOOK_ENV_VARS = (
    "DROID_AZURE_TOKEN_X_API_KEY",
    "DROID_AZURE_TOKEN_HEADER",
    "DROID_AZURE_TOKEN_HEADER_VALUE",
)


@pytest.fixture(autouse=True)
def clean_token_hook_env(monkeypatch):
    """Make sure the tests are not influenced by the environment"""
    for name in TOKEN_HOOK_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_token_hook_headers_without_any_env_var():
    assert get_token_hook_headers() == {}


def test_token_hook_headers_with_api_key(monkeypatch):
    monkeypatch.setenv("DROID_AZURE_TOKEN_X_API_KEY", "secret")
    assert get_token_hook_headers() == {"X-API-Key": "secret"}


def test_token_hook_headers_with_custom_header(monkeypatch):
    monkeypatch.setenv("DROID_AZURE_TOKEN_HEADER", "foo")
    monkeypatch.setenv("DROID_AZURE_TOKEN_HEADER_VALUE", "bar")
    assert get_token_hook_headers() == {"foo": "bar"}


def test_token_hook_headers_custom_header_takes_precedence(monkeypatch):
    monkeypatch.setenv("DROID_AZURE_TOKEN_X_API_KEY", "secret")
    monkeypatch.setenv("DROID_AZURE_TOKEN_HEADER", "foo")
    monkeypatch.setenv("DROID_AZURE_TOKEN_HEADER_VALUE", "bar")
    assert get_token_hook_headers() == {"foo": "bar"}


def test_token_hook_headers_with_custom_header_name_only(monkeypatch):
    monkeypatch.setenv("DROID_AZURE_TOKEN_HEADER", "foo")
    with pytest.raises(ValueError, match="DROID_AZURE_TOKEN_HEADER_VALUE"):
        get_token_hook_headers()


def test_token_hook_headers_with_custom_header_value_only(monkeypatch):
    monkeypatch.setenv("DROID_AZURE_TOKEN_HEADER_VALUE", "bar")
    with pytest.raises(ValueError, match="DROID_AZURE_TOKEN_HEADER"):
        get_token_hook_headers()
