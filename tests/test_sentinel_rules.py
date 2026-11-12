"""
Tests of the analytics rule droid builds for Sentinel
"""

import copy

import pytest

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


def _export(monkeypatch, rule=SIGMA_RULE, query="SigninLogs", **parameters):
    """Export a rule with the Azure client stubbed out

    Return: the properties of each rule pushed, as sent to the API
    """

    pushed = []

    class FakeAlertRules:
        def create_or_update(self, resource_group_name, workspace_name, rule_id, alert_rule):
            pushed.append(alert_rule.serialize())

    class FakeSecurityInsights:
        def __init__(self, credential, subscription_id):
            self.alert_rules = FakeAlertRules()

    monkeypatch.setattr(sentinel, "SecurityInsights", FakeSecurityInsights)

    platform = sentinel.SentinelPlatform({**PARAMETERS, **parameters}, LOGGER_PARAM)
    platform.get_credentials = lambda: None
    platform.create_rule(copy.deepcopy(rule), query, "rule.yml")

    return pushed


def _with_custom(**custom):
    return {**SIGMA_RULE, "custom": custom}


def test_suppression_disabled_still_sends_a_duration(monkeypatch):
    """The API rejects a rule without suppressionDuration, even when
    suppression is off: 'Required property suppressionDuration not found'."""

    [rule] = _export(monkeypatch, suppress_status=False)

    assert rule["properties"]["suppressionEnabled"] is False
    assert rule["properties"]["suppressionDuration"] == "PT2H"


def test_suppression_enabled(monkeypatch):
    [rule] = _export(monkeypatch, suppress_status=True)

    assert rule["properties"]["suppressionEnabled"] is True
    assert rule["properties"]["suppressionDuration"] == "PT2H"


def test_grouping_disabled_is_sent_as_disabled(monkeypatch):
    [rule] = _export(monkeypatch, grouping_status=False)

    grouping = rule["properties"]["incidentConfiguration"]["groupingConfiguration"]
    assert grouping["enabled"] is False


def test_grouping_enabled_with_rule_overrides(monkeypatch):
    rule = _with_custom(grouping_period=12, grouping_matching_entities=["Account"])

    [pushed] = _export(monkeypatch, rule=rule)

    grouping = pushed["properties"]["incidentConfiguration"]["groupingConfiguration"]
    assert grouping["enabled"] is True
    assert grouping["lookbackDuration"] == "PT12H"
    assert grouping["matchingMethod"] == "Selected"
    assert grouping["groupByEntities"] == ["Account"]


def test_scheduled_rule_by_default(monkeypatch):
    [rule] = _export(monkeypatch)

    assert rule["kind"] == "Scheduled"
    assert rule["properties"]["queryFrequency"] == "PT1H"
    assert rule["properties"]["queryPeriod"] == "PT2H"
    assert rule["properties"]["triggerOperator"] == "GreaterThan"
    assert rule["properties"]["triggerThreshold"] == 0


def test_scheduled_rule_overrides(monkeypatch):
    [rule] = _export(monkeypatch, rule=_with_custom(query_frequency=4, query_period=8))

    assert rule["properties"]["queryFrequency"] == "PT4H"
    assert rule["properties"]["queryPeriod"] == "PT8H"


@pytest.mark.parametrize("query_period", [0, "0"])
def test_query_period_zero_makes_a_nrt_rule(monkeypatch, query_period):
    """custom.query_period: 0 is how a rule asks for NRT on Defender XDR, so
    the same rule is near real-time on Sentinel too."""

    [rule] = _export(monkeypatch, rule=_with_custom(query_period=query_period))

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
    query, which must keep every other setting, the kind included."""

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

    pushed = []

    class FakeAlertRules:
        def create_or_update(self, resource_group_name, workspace_name, rule_id, alert_rule):
            pushed.append(alert_rule.serialize())

    class FakeSecurityInsights:
        def __init__(self, credential, subscription_id):
            self.alert_rules = FakeAlertRules()

    monkeypatch.setattr(sentinel, "SecurityInsights", FakeSecurityInsights)

    platform = sentinel.SentinelPlatform(
        {**PARAMETERS, "export_list_mssp": customers}, LOGGER_PARAM, export_mssp=True
    )
    platform.get_credentials = lambda: None
    platform.set_convert_rule_callback(lambda *args: "SigninLogs | where Customer == 'zoidberg'")
    platform.create_rule(_with_custom(query_period=0), "SigninLogs", "rule.yml")

    [rule] = pushed
    assert rule["kind"] == "NRT"
    assert rule["properties"]["query"] == "SigninLogs | where Customer == 'zoidberg'"
    assert rule["properties"]["suppressionDuration"] == "PT2H"
