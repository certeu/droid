"""
Tests of the Sentinel search error handling

A search that could not run, entirely or in one workspace, or that only
returned a partial result, is an error: droid must not report the rule as
searched, and must log the reason the platform gave.
"""

import pytest

from azure.core.exceptions import HttpResponseError

from droid import search as search_module
from droid.platforms import sentinel
from droid.search import search_rule_sentinel, search_rule_sentinel_mssp


LOGGER_PARAM = {"debug_mode": False, "json_enabled": False}

RULE_FILE = "rules/sigma/delivery/anchovy_smuggling_on_neptune.yml"
RULE_CONTENT = {"id": "0c1b1b1a-0000-0000-0000-0000deadbeef", "title": "Anchovy smuggling"}

PARAMETERS = {
    "threshold_operator": "GreaterThan",
    "threshold_value": 0,
    "suppress_status": False,
    "incident_status": True,
    "grouping_reopen": False,
    "grouping_status": False,
    "grouping_period": 24,
    "grouping_method": "AllEntityMatch",
    "query_frequency": 1,
    "query_period": 1,
    "subscription_id": "sub-new-new-york",
    "resource_group": "rg-planet-express",
    "workspace_id": "ws-planet-express",
    "workspace_name": "planet-express",
    "days_ago": 1,
    "timeout": 60,
    "search_auth": "default",
    "export_auth": "default",
}

CUSTOMERS = {
    "group1": {
        "tenant_id": "tenant-planet-express",
        "workspace_id": "ws-planet-express",
        "workspace_name": "planet-express",
        "customer_name": "Planet Express",
    },
    "group2": {
        "tenant_id": "tenant-panucci",
        "workspace_id": "ws-panucci",
        "workspace_name": "panucci",
        "customer_name": "Panucci's Pizza",
    },
}


class RecordingLogger:
    """Stand-in for ColorLogger capturing the emitted messages"""

    def __init__(self, *args, **kwargs):
        self.records = []

    def debug(self, message, *args, **kwargs):
        self.records.append(("DEBUG", message))

    def info(self, message, *args, **kwargs):
        self.records.append(("INFO", message))

    def warning(self, message, *args, **kwargs):
        self.records.append(("WARNING", message))

    def error(self, message, *args, **kwargs):
        self.records.append(("ERROR", message))

    def messages(self, level):
        return [message for lvl, message in self.records if lvl == level]


class FakeTable:
    def __init__(self, rows):
        self.rows = rows


class FakeResults:
    def __init__(self, hits):
        self.status = sentinel.LogsQueryStatus.SUCCESS
        self.tables = [FakeTable([("row",)] * hits)]


class FakePartialResults:
    """What the SDK returns when the query only ran in part: no tables"""

    def __init__(self):
        self.status = sentinel.LogsQueryStatus.PARTIAL
        self.partial_error = "Bender ate the rest of the results"
        self.partial_data = []


def fake_logs_query_client(monkeypatch, answers):
    """Make LogsQueryClient answer each workspace from answers: a hit count,
    a result object, or an exception to raise"""

    class FakeLogsQueryClient:
        def __init__(self, credential):
            pass

        def _answer(self, workspace_id):
            answer = answers[workspace_id]
            if isinstance(answer, Exception):
                raise answer
            if isinstance(answer, int):
                return FakeResults(answer)
            return answer

        def query_workspace(self, workspace_id, query, timespan=None, server_timeout=None):
            return self._answer(workspace_id)

        def query_resource(self, resource_id, query, timespan=None, server_timeout=None):
            return self._answer(resource_id)

    monkeypatch.setattr(sentinel, "LogsQueryClient", FakeLogsQueryClient)


@pytest.fixture
def logger(monkeypatch):
    """Capture what droid.search logs instead of printing it"""
    recorder = RecordingLogger()
    monkeypatch.setattr(search_module, "ColorLogger", lambda *a, **kw: recorder)
    return recorder


def build_platform(monkeypatch, **overrides):
    platform = sentinel.SentinelPlatform({**PARAMETERS, **overrides}, LOGGER_PARAM)
    platform.logger = RecordingLogger()
    monkeypatch.setattr(platform, "get_credentials", lambda **kwargs: None)
    return platform


def search_single(platform, logger):
    return search_rule_sentinel(
        "SecurityEvent", RULE_CONTENT, platform, RULE_FILE,
        parameters={}, logger=logger, error=False, search_warning=False, mssp_mode=False,
    )


def search_all_workspaces(platform, logger):
    return search_rule_sentinel(
        "SecurityEvent", RULE_CONTENT, platform, RULE_FILE,
        parameters={}, logger=logger, error=False, search_warning=False, mssp_mode=True,
    )


def search_designated(platform, logger):
    return search_rule_sentinel_mssp(
        "SecurityEvent", RULE_CONTENT, platform, RULE_FILE,
        parameters={}, logger=logger, error=False, search_warning=False,
    )


# Single workspace

def test_single_workspace_search_failure_logs_the_real_error(monkeypatch, logger):
    """The error of the platform is reported, not a comparison with None"""
    fake_logs_query_client(monkeypatch, {"ws-planet-express": HttpResponseError("Insufficient permissions")})
    platform = build_platform(monkeypatch)

    error, search_warning = search_single(platform, logger)

    assert error is True
    [message] = logger.messages("ERROR")
    assert message.startswith(f"Couldn't search for the rule {RULE_FILE} - error ")
    assert "Insufficient permissions" in message
    assert "NoneType" not in message
    assert f"Successfully searched the rule {RULE_FILE}" not in logger.messages("INFO")


def test_single_workspace_partial_result_is_an_error(monkeypatch, logger):
    fake_logs_query_client(monkeypatch, {"ws-planet-express": FakePartialResults()})
    platform = build_platform(monkeypatch)

    error, search_warning = search_single(platform, logger)

    assert error is True
    [message] = logger.messages("ERROR")
    assert "Bender ate the rest of the results" in message
    assert "NoneType" not in message


def test_single_workspace_search_returns_the_hits(monkeypatch, logger):
    fake_logs_query_client(monkeypatch, {"ws-planet-express": 2})
    platform = build_platform(monkeypatch)

    error, search_warning = search_single(platform, logger)

    assert error is False
    assert search_warning is True
    assert f"(Sentinel) 2 hit(s) found for {RULE_FILE}" in logger.messages("WARNING")


# MSSP, every workspace the managing tenant sees

def _all_workspaces_platform(monkeypatch):
    platform = build_platform(monkeypatch)
    platform._client_workspaces = [
        {"customer": "planet-express", "workspace_id": "ws-planet-express"},
        {"customer": "panucci", "workspace_id": "ws-panucci"},
    ]
    return platform


def test_all_workspaces_search_failure_is_an_error_and_keeps_searching(monkeypatch, logger):
    """One workspace failing does not stop the others from being searched,
    and their hits are still reported"""
    fake_logs_query_client(monkeypatch, {
        "ws-planet-express": HttpResponseError("Workspace not found"),
        "ws-panucci": 3,
    })
    platform = _all_workspaces_platform(monkeypatch)

    error, search_warning = search_all_workspaces(platform, logger)

    assert error is True
    assert any("Workspace not found" in m and "planet-express" in m for m in platform.logger.messages("ERROR"))
    assert (
        f"(Sentinel MSSP) 3 hit(s) found for {RULE_FILE} on customer 'panucci'"
        in platform.logger.messages("WARNING")
    )
    assert "NoneType" not in logger.messages("ERROR")[0]
    assert f"Successfully searched the rule {RULE_FILE}" not in logger.messages("INFO")


def test_all_workspaces_partial_result_is_an_error(monkeypatch, logger):
    fake_logs_query_client(monkeypatch, {"ws-planet-express": FakePartialResults(), "ws-panucci": 0})
    platform = _all_workspaces_platform(monkeypatch)

    error, search_warning = search_all_workspaces(platform, logger)

    assert error is True
    assert any("Bender ate the rest of the results" in m for m in platform.logger.messages("ERROR"))


def test_all_workspaces_search_succeeds(monkeypatch, logger):
    fake_logs_query_client(monkeypatch, {"ws-planet-express": 1, "ws-panucci": 0})
    platform = _all_workspaces_platform(monkeypatch)

    error, search_warning = search_all_workspaces(platform, logger)

    assert error is False
    assert search_warning is True


# MSSP, designated customers of export_list_mssp

def test_designated_search_fails_when_every_workspace_fails(monkeypatch, logger):
    """A search that ran nowhere is not a successful search"""
    platform = build_platform(monkeypatch, export_list_mssp=CUSTOMERS)

    def failing_credentials(**kwargs):
        raise Exception("Custom token acquisition failed")

    monkeypatch.setattr(platform, "get_credentials", failing_credentials)

    error, search_warning = search_designated(platform, logger)

    assert error is True
    assert f"Successfully searched the rule {RULE_FILE}" not in logger.messages("INFO")
    workspace_errors = platform.logger.messages("ERROR")
    assert any("planet-express" in m and "Custom token acquisition failed" in m for m in workspace_errors)
    assert any("panucci" in m and "Custom token acquisition failed" in m for m in workspace_errors)


def test_designated_search_keeps_searching_after_a_workspace_error(monkeypatch, logger):
    """One customer being down does not stop the others from being searched,
    and the hits found there are still reported"""
    fake_logs_query_client(monkeypatch, {
        "ws-planet-express": HttpResponseError("Workspace not found"),
        "ws-panucci": 2,
    })
    platform = build_platform(monkeypatch, export_list_mssp=CUSTOMERS)

    error, search_warning = search_designated(platform, logger)

    assert error is True
    assert any("Workspace not found" in m for m in platform.logger.messages("ERROR"))
    assert (
        f"(Sentinel MSSP) 2 hit(s) found for {RULE_FILE} on customer 'Panucci's Pizza'"
        in platform.logger.messages("WARNING")
    )
    [message] = logger.messages("ERROR")
    assert message.startswith(f"Couldn't search for the rule {RULE_FILE} - error ")


def test_designated_partial_result_is_an_error(monkeypatch, logger):
    fake_logs_query_client(monkeypatch, {"ws-planet-express": FakePartialResults(), "ws-panucci": 0})
    platform = build_platform(monkeypatch, export_list_mssp=CUSTOMERS)

    error, search_warning = search_designated(platform, logger)

    assert error is True
    assert any("Bender ate the rest of the results" in m for m in platform.logger.messages("ERROR"))


def test_designated_search_without_export_list_is_an_error(monkeypatch, logger):
    platform = build_platform(monkeypatch)

    error, search_warning = search_designated(platform, logger)

    assert error is True


def test_designated_search_succeeds(monkeypatch, logger):
    fake_logs_query_client(monkeypatch, {"ws-planet-express": 0, "ws-panucci": 1})
    platform = build_platform(monkeypatch, export_list_mssp=CUSTOMERS)

    error, search_warning = search_designated(platform, logger)

    assert error is False
    assert search_warning is True
    assert f"(Sentinel MSSP) 1 hit(s) found in total for {RULE_FILE}" in logger.messages("WARNING")
