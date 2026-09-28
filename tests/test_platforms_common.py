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


# ---------------------------------------------------------------------------
# Suppression fields resolution
# ---------------------------------------------------------------------------

SUPPRESS_GROUPS = {
    "windows_process_creation": {
        "product": "windows",
        "category": "process_creation",
        "alert.suppress.fields": "Computer,CommandLine",
    }
}

PROCESS_CREATION_RULE = {
    "logsource": {"category": "process_creation", "product": "windows"},
}


def test_suppress_fields_come_from_the_matching_log_source_group():
    """Unchanged behaviour for a rule with no variant."""
    from droid.platforms.common import get_suppress_fields

    assert get_suppress_fields(PROCESS_CREATION_RULE, SUPPRESS_GROUPS) == "Computer,CommandLine"


def test_suppress_fields_are_none_when_no_group_matches():
    from droid.platforms.common import get_suppress_fields

    assert get_suppress_fields(
        {"logsource": {"category": "network_connection", "product": "windows"}},
        SUPPRESS_GROUPS,
    ) is None


def test_variant_overrides_the_log_source_suppress_fields():
    """BitDefender field names differ from Sysmon's, so the log-source-wide
    suppression fields do not exist in the variant's data and must not be used."""
    from droid.platforms.common import get_suppress_fields

    rule_content = {
        **PROCESS_CREATION_RULE,
        "_droid_variant": {
            "name": "bitdefender",
            "config": {"variant": "bitdefender", "alert.suppress.fields": "aid,process_path"},
        },
    }

    assert get_suppress_fields(rule_content, SUPPRESS_GROUPS) == "aid,process_path"


def test_variant_without_an_override_inherits_the_log_source_fields():
    """A variant whose schema matches the primary's should not have to restate them."""
    from droid.platforms.common import get_suppress_fields

    rule_content = {
        **PROCESS_CREATION_RULE,
        "_droid_variant": {"name": "sysmon", "config": {"variant": "sysmon"}},
    }

    assert get_suppress_fields(rule_content, SUPPRESS_GROUPS) == "Computer,CommandLine"
