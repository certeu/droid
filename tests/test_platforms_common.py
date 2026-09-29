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
    """third-party EDR field names differ from Sysmon's, so the log-source-wide
    suppression fields do not exist in the variant's data and must not be used."""
    from droid.platforms.common import get_suppress_fields

    rule_content = {
        **PROCESS_CREATION_RULE,
        "_droid_variant": {
            "name": "edr",
            "config": {"variant": "edr", "alert.suppress.fields": "aid,process_path"},
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


# ---------------------------------------------------------------------------
# Search lookback resolution
# ---------------------------------------------------------------------------


class WarningRecorder:
    """Stand-in for ColorLogger keeping only what was warned about"""

    def __init__(self):
        self.warnings = []

    def warning(self, message, *args, **kwargs):
        self.warnings.append(message)


def test_search_days_ago_defaults_to_the_platform_value():
    """A rule saying nothing keeps the lookback configured for the platform."""
    from droid.platforms.common import get_search_days_ago

    logger = WarningRecorder()

    assert get_search_days_ago({"title": "Anchovy smuggling"}, 1, logger) == 1
    assert logger.warnings == []


def test_search_days_ago_is_overridden_by_the_custom_field():
    """Some detections only show up over a longer window than the platform default."""
    from droid.platforms.common import get_search_days_ago

    logger = WarningRecorder()
    rule_content = {"custom": {"days_ago": 7}}

    assert get_search_days_ago(rule_content, 1, logger) == 7
    assert logger.warnings == []


def test_search_days_ago_without_any_rule_content():
    """The raw search path can reach a platform with no rule content at all."""
    from droid.platforms.common import get_search_days_ago

    assert get_search_days_ago(None, 3, WarningRecorder()) == 3


def test_search_days_ago_rejects_a_value_that_is_not_a_positive_integer():
    """A malformed field in one rule must not abort the whole run."""
    from droid.platforms.common import get_search_days_ago

    for value in ["7", 0, -1, 1.5, True]:
        logger = WarningRecorder()
        rule_content = {"custom": {"days_ago": value}}

        assert get_search_days_ago(rule_content, 2, logger) == 2
        assert len(logger.warnings) == 1
        assert "days_ago" in logger.warnings[0]


def test_search_days_ago_is_capped_at_the_platform_maximum():
    """Microsoft XDR refuses a hunting timespan beyond 30 days."""
    from droid.platforms.common import get_search_days_ago

    logger = WarningRecorder()
    rule_content = {"custom": {"days_ago": 90}}

    assert get_search_days_ago(rule_content, 1, logger, maximum=30) == 30
    assert len(logger.warnings) == 1
    assert "30" in logger.warnings[0]


def test_search_days_ago_allows_the_maximum_itself():
    from droid.platforms.common import get_search_days_ago

    logger = WarningRecorder()

    assert get_search_days_ago({"custom": {"days_ago": 30}}, 1, logger, maximum=30) == 30
    assert logger.warnings == []
