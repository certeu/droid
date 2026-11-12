"""
Tests of the analytics rule droid builds for Sentinel
"""

import copy

import pytest

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

from droid.platforms import sentinel


LOGGER_PARAM = {"debug_mode": False, "json_enabled": False}

SIGMA_RULE = {
    "id": "a0ed3af5-4d03-45a6-878e-b27c0baa1e31",
    "title": "Sign-in using the Entra ID break-glass account",
    "description": "A break-glass account signed in",
    "level": "critical",
    "status": "stable",
    "tags": ["attack.privilege-escalation", "attack.t1078.004"],
    "logsource": {"product": "azure", "service": "signinlogs"},
}

PARAMETERS = {
    "threshold_operator": "GreaterThan",
    "threshold_value": 0,
    "suppress_status": False,
    "incident_status": True,
    "grouping_reopen": False,
    "grouping_status": True,
    "grouping_period": 5,
    "grouping_method": "AllEntities",
    "suppress_period": 2,
    "query_frequency": 1,
    "query_period": 2,
    "subscription_id": "sub-default",
    "resource_group": "rg-default",
    "workspace_id": "ws-default",
    "workspace_name": "workspace-default",
    "days_ago": 1,
    "timeout": 120,
    "search_auth": "default",
    "export_auth": "default",
}


class FakeAzure:
    """Stands in for the Sentinel API: the rule deployed in each workspace,
    and every call droid makes"""

    def __init__(self, monkeypatch, deployed=None, fail_create=False):
        self.deployed = dict(deployed or {})
        self.calls = []
        self.pushed = []
        azure = self

        class FakeAlertRules:
            def get(self, resource_group_name, workspace_name, rule_id):
                azure.calls.append(("get", workspace_name))
                if workspace_name not in azure.deployed:
                    raise ResourceNotFoundError("Not found")
                return azure.deployed[workspace_name]

            def delete(self, resource_group_name, workspace_name, rule_id):
                azure.calls.append(("delete", workspace_name))
                del azure.deployed[workspace_name]

            def create_or_update(self, resource_group_name, workspace_name, rule_id, alert_rule):
                azure.calls.append(("create", workspace_name))
                if fail_create:
                    raise HttpResponseError("Refused")
                azure.pushed.append(alert_rule.serialize())
                azure.deployed[workspace_name] = alert_rule

        class FakeSecurityInsights:
            def __init__(self, credential, subscription_id):
                self.alert_rules = FakeAlertRules()

        monkeypatch.setattr(sentinel, "SecurityInsights", FakeSecurityInsights)


@pytest.fixture
def azure(monkeypatch):
    return FakeAzure(monkeypatch)


def _export(azure, rule=SIGMA_RULE, query="SigninLogs", parameters=PARAMETERS, **overrides):
    """Export a rule through the fake API

    Return: each rule pushed, as sent to the API
    """

    platform = sentinel.SentinelPlatform({**parameters, **overrides}, LOGGER_PARAM)
    platform.get_credentials = lambda: None
    platform.create_rule(copy.deepcopy(rule), query, "rule.yml")

    return azure.pushed


def _with_custom(**custom):
    return {**SIGMA_RULE, "custom": custom}


def test_suppression_disabled_still_sends_a_duration(azure):
    """The API rejects a rule without suppressionDuration, even when
    suppression is off: 'Required property suppressionDuration not found'."""

    [rule] = _export(azure, suppress_status=False)

    assert rule["properties"]["suppressionEnabled"] is False
    assert rule["properties"]["suppressionDuration"] == "PT2H"


def test_suppression_enabled(azure):
    [rule] = _export(azure, suppress_status=True)

    assert rule["properties"]["suppressionEnabled"] is True
    assert rule["properties"]["suppressionDuration"] == "PT2H"


def test_grouping_disabled_is_sent_as_disabled(azure):
    [rule] = _export(azure, grouping_status=False)

    grouping = rule["properties"]["incidentConfiguration"]["groupingConfiguration"]
    assert grouping["enabled"] is False


def test_grouping_enabled_with_rule_overrides(azure):
    rule = _with_custom(grouping_period=12, grouping_matching_entities=["Account"])

    [pushed] = _export(azure, rule=rule)

    grouping = pushed["properties"]["incidentConfiguration"]["groupingConfiguration"]
    assert grouping["enabled"] is True
    assert grouping["lookbackDuration"] == "PT12H"
    assert grouping["matchingMethod"] == "Selected"
    assert grouping["groupByEntities"] == ["Account"]


def test_scheduled_rule_by_default(azure):
    [rule] = _export(azure)

    assert rule["kind"] == "Scheduled"
    assert rule["properties"]["queryFrequency"] == "PT1H"
    assert rule["properties"]["queryPeriod"] == "PT2H"
    assert rule["properties"]["triggerOperator"] == "GreaterThan"
    assert rule["properties"]["triggerThreshold"] == 0


def test_scheduled_rule_overrides(azure):
    [rule] = _export(azure, rule=_with_custom(query_frequency=4, query_period=8))

    assert rule["properties"]["queryFrequency"] == "PT4H"
    assert rule["properties"]["queryPeriod"] == "PT8H"


@pytest.mark.parametrize("query_period", [0, "0"])
def test_query_period_zero_makes_a_nrt_rule(azure, query_period):
    """custom.query_period: 0 is how a rule asks for NRT on Defender XDR, so
    the same rule is near real-time on Sentinel too."""

    [rule] = _export(azure, rule=_with_custom(query_period=query_period))

    assert rule["kind"] == "NRT"
    assert "queryFrequency" not in rule["properties"]
    assert "queryPeriod" not in rule["properties"]
    assert "triggerOperator" not in rule["properties"]
    assert rule["properties"]["query"] == "SigninLogs"
    assert rule["properties"]["suppressionEnabled"] is False
    assert rule["properties"]["suppressionDuration"] == "PT2H"
    assert rule["properties"]["incidentConfiguration"]["createIncident"] is True
    assert rule["properties"]["severity"] == "high"


def test_nrt_rule_reconverted_for_a_customer_stays_nrt(monkeypatch):
    """A customer with its own filters gets a copy of the rule with its own
    query, which must keep every other setting, the kind included, and
    replace the scheduled rule deployed there."""

    customers = {
        "Zoidberg": {
            "tenant_id": "tenant-zoidberg",
            "customer_name": "Zoidberg",
            "subscription_id": "sub-zoidberg",
            "resource_group_name": "rg-zoidberg",
            "workspace_name": "workspace-zoidberg",
            "customer_filters_directory": "filters/zoidberg",
        },
    }

    azure = FakeAzure(monkeypatch, deployed={"workspace-zoidberg": _deployed("Scheduled")})
    platform = sentinel.SentinelPlatform(
        {**PARAMETERS, "export_list_mssp": customers}, LOGGER_PARAM, export_mssp=True
    )
    platform.get_credentials = lambda: None
    platform.set_convert_rule_callback(lambda *args: "SigninLogs | where Customer == 'zoidberg'")
    platform.create_rule(_with_custom(query_period=0), "SigninLogs", "rule.yml")

    [rule] = azure.pushed
    assert rule["kind"] == "NRT"
    assert rule["properties"]["query"] == "SigninLogs | where Customer == 'zoidberg'"
    assert rule["properties"]["suppressionDuration"] == "PT2H"
    assert ("delete", "workspace-zoidberg") in azure.calls


def test_suppress_period_is_optional_with_suppression_off(azure):
    """suppress_period only matters with suppression on, but the API still
    wants a duration: droid sends one of its own."""

    parameters = {key: value for key, value in PARAMETERS.items() if key != "suppress_period"}

    [rule] = _export(azure, parameters=parameters)

    assert rule["properties"]["suppressionEnabled"] is False
    assert rule["properties"]["suppressionDuration"] == "PT5H"


def test_suppress_period_is_required_with_suppression_on():
    parameters = {key: value for key, value in PARAMETERS.items() if key != "suppress_period"}

    with pytest.raises(Exception, match="suppress_period"):
        sentinel.SentinelPlatform({**parameters, "suppress_status": True}, LOGGER_PARAM)


def _deployed(kind):
    rule_class = sentinel.NrtAlertRule if kind == "NRT" else sentinel.ScheduledAlertRule
    return rule_class(query="SigninLogs", display_name="Deployed")


def test_a_rule_switched_to_nrt_replaces_the_deployed_one(monkeypatch):
    """Sentinel may not change the kind of a deployed rule in place: droid
    deletes it, then creates the NRT rule."""

    azure = FakeAzure(monkeypatch, deployed={"workspace-default": _deployed("Scheduled")})

    [rule] = _export(azure, rule=_with_custom(query_period=0))

    assert rule["kind"] == "NRT"
    assert azure.calls == [("get", "workspace-default"), ("delete", "workspace-default"),
                           ("create", "workspace-default")]


def test_a_rule_switched_back_to_scheduled_replaces_the_deployed_one(monkeypatch):
    azure = FakeAzure(monkeypatch, deployed={"workspace-default": _deployed("NRT")})

    [rule] = _export(azure)

    assert rule["kind"] == "Scheduled"
    assert ("delete", "workspace-default") in azure.calls


@pytest.mark.parametrize("deployed", [{}, {"workspace-default": _deployed("Scheduled")}])
def test_a_rule_keeping_its_kind_is_updated_in_place(monkeypatch, deployed):
    azure = FakeAzure(monkeypatch, deployed=deployed)

    _export(azure)

    assert azure.calls == [("get", "workspace-default"), ("create", "workspace-default")]


def test_a_failed_kind_switch_says_the_rule_is_gone(monkeypatch):
    """Once deleted, a rule which cannot be created again no longer runs:
    the error has to say so, not only that the export failed."""

    azure = FakeAzure(monkeypatch, deployed={"workspace-default": _deployed("Scheduled")}, fail_create=True)
    platform = sentinel.SentinelPlatform(PARAMETERS, LOGGER_PARAM)
    platform.get_credentials = lambda: None
    errors = []
    platform.logger.error = lambda message, *args, **kwargs: errors.append(message)

    with pytest.raises(HttpResponseError):
        platform.create_rule(_with_custom(query_period=0), "SigninLogs", "rule.yml")

    assert "workspace-default" not in azure.deployed
    assert any("no longer deployed" in message for message in errors)


def test_rule_kind():
    assert sentinel.sentinel_rule_kind(SIGMA_RULE) == "Scheduled"
    assert sentinel.sentinel_rule_kind(_with_custom(query_period=2)) == "Scheduled"
    assert sentinel.sentinel_rule_kind(_with_custom(query_period=0)) == "NRT"
    assert sentinel.sentinel_rule_kind(_with_custom(query_period="0")) == "NRT"
