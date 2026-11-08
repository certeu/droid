"""
Tests of the custom detection rules droid deploys on Microsoft XDR

The payloads follow the Graph v1.0 detectionRule resource: Microsoft removed
isEnabled, schedule.period, category, mitreTechniques, impactedAssets and
responseActions on 2026-10-01, in favour of status, schedule.frequency,
tactics, entityMappings and automatedActions.
"""

import copy

import pytest

from droid.platforms.ms_xdr import MicrosoftXDRPlatform

LOGGER_PARAM = {"debug_mode": False, "json_enabled": False}

RULE_FILE = "rules/sigma/delivery/anchovy_smuggling_on_neptune.yml"

XDR_PARAMETERS = {
    "query_period": "1h",
    "days_ago": 1,
    "tenant_id": "tenant-planet-express",
    "search_auth": "default",
    "export_auth": "default",
}


def build_rule_content(custom=None, tags=None, level="high"):
    rule_content = {
        "id": "8d3b2a6e-6f0a-4c1e-9a52-1f2e3d4c5b6a",
        "title": "Anchovy smuggling on Neptune",
        "description": "Hermes spotted crates of anchovies in the cargo hold",
        "level": level,
        "tags": tags if tags is not None else ["attack.execution", "attack.t1059"],
    }
    if custom is not None:
        rule_content["custom"] = custom
    return rule_content


@pytest.fixture
def platform():
    return MicrosoftXDRPlatform(dict(XDR_PARAMETERS), LOGGER_PARAM)


@pytest.fixture
def pushed(platform, monkeypatch):
    """Capture the payloads create_rule would send, sending nothing"""

    payloads = []

    def fake_push(alert_rule=None, **kwargs):
        payloads.append(copy.deepcopy(alert_rule))
        return True

    monkeypatch.setattr(platform, "push_detection_rule", fake_push)
    return payloads


def alert_template(payload):
    return payload["detectionAction"]["alertTemplate"]


# Entity mappings


def test_xdr_entity_mappings_are_pushed_as_entity_mappings(platform, pushed):
    custom = {
        "xdr_entity_mappings": [
            {
                "entity_type": "accounts",
                "field_mappings": [
                    {"identifier": "upnColumn", "column_name": "AccountUpn"},
                    {"identifier": "sidColumn", "column_name": "AccountSid"},
                ],
            },
            {
                "entity_type": "hosts",
                "field_mappings": [{"identifier": "deviceIdColumn", "column_name": "DeviceId"}],
            },
        ]
    }

    platform.create_rule(build_rule_content(custom), "DeviceEvents", RULE_FILE)

    assert alert_template(pushed[0])["entityMappings"] == {
        "accounts": [{"upnColumn": "AccountUpn", "sidColumn": "AccountSid"}],
        "hosts": [{"deviceIdColumn": "DeviceId"}],
    }


def test_sentinel_entity_mappings_are_left_to_sentinel(platform, pushed):
    """custom.entity_mappings holds Sentinel's vocabulary, which XDR rejects:
    a rule written for both platforms must still export to XDR."""

    custom = {
        "entity_mappings": [
            {
                "entity_type": "Account",
                "field_mappings": [{"identifier": "FullName", "column_name": "AccountUpn"}],
            }
        ]
    }

    platform.create_rule(build_rule_content(custom), "DeviceEvents", RULE_FILE)

    assert "entityMappings" not in alert_template(pushed[0])


def test_legacy_impacted_assets_are_no_longer_pushed(platform, pushed):
    custom = {"impactedAssets": [{"impactedAssetType": "device", "identifier": "deviceId"}]}

    platform.create_rule(build_rule_content(custom), "DeviceEvents", RULE_FILE)

    assert "impactedAssets" not in alert_template(pushed[0])


@pytest.mark.parametrize(
    "mapping",
    [
        {"entity_type": "Account", "field_mappings": [{"identifier": "upnColumn", "column_name": "Upn"}]},
        {"entity_type": "accounts", "field_mappings": [{"identifier": "FullName", "column_name": "Upn"}]},
        {"entity_type": "accounts", "field_mappings": [{"identifier": "upnColumn"}]},
        {"entity_type": "accounts", "field_mappings": []},
    ],
    ids=["unknown-entity-type", "unknown-column", "missing-column-name", "no-field-mappings"],
)
def test_an_invalid_entity_mapping_is_an_error(platform, mapping):
    with pytest.raises(ValueError):
        platform.parse_entity_mappings([mapping], rule_file=RULE_FILE)


# Status and schedule


def test_an_enabled_rule_is_pushed_with_status_enabled(platform, pushed):
    platform.create_rule(build_rule_content(), "DeviceEvents", RULE_FILE)

    assert pushed[0]["status"] == "enabled"
    assert "isEnabled" not in pushed[0]


def test_a_disabled_rule_is_pushed_with_status_disabled(platform, pushed):
    platform.create_rule(build_rule_content({"disabled": True}), "DeviceEvents", RULE_FILE)

    assert pushed[0]["status"] == "disabled"


@pytest.mark.parametrize(
    "query_period, frequency",
    [("1h", "PT1H"), ("3H", "PT3H"), ("12H", "PT12H"), ("24H", "P1D")],
)
def test_the_query_period_is_pushed_as_a_frequency(platform, pushed, query_period, frequency):
    platform.create_rule(build_rule_content({"query_period": query_period}), "DeviceEvents", RULE_FILE)

    assert pushed[0]["schedule"] == {"frequency": frequency}


def test_the_configured_query_period_applies_by_default(platform, pushed):
    platform.create_rule(build_rule_content(), "DeviceEvents", RULE_FILE)

    assert pushed[0]["schedule"] == {"frequency": "PT1H"}


def test_a_rule_query_period_overrides_a_continuous_configuration(pushed, monkeypatch):
    """Only the query_period that wins is translated: a continuous default
    must not fail the rules that set their own."""

    platform = MicrosoftXDRPlatform(dict(XDR_PARAMETERS, query_period="0"), LOGGER_PARAM)
    monkeypatch.setattr(platform, "push_detection_rule", lambda alert_rule=None, **kwargs: pushed.append(alert_rule))

    platform.create_rule(build_rule_content({"query_period": "12H"}), "DeviceEvents", RULE_FILE)

    assert pushed[0]["schedule"] == {"frequency": "PT12H"}


@pytest.mark.parametrize("query_period", ["0", "2H", "PT1H"])
def test_a_query_period_without_a_frequency_is_an_error(platform, pushed, query_period):
    """Graph documents no frequency for a continuous rule, so droid refuses
    one rather than deploying a rule that runs on another schedule."""

    with pytest.raises(ValueError):
        platform.create_rule(build_rule_content({"query_period": query_period}), "DeviceEvents", RULE_FILE)

    assert pushed == []



# MITRE tactics


def test_tags_are_pushed_as_tactics(platform, pushed):
    rule_content = build_rule_content(tags=["attack.execution", "attack.t1059.001", "attack.t1059.003", "attack.t1204"])

    platform.create_rule(rule_content, "DeviceEvents", RULE_FILE)

    template = alert_template(pushed[0])
    assert template["tactics"] == [
        {
            "tactic": "Execution",
            "techniques": [
                {"technique": "T1059", "subTechniques": ["T1059.001", "T1059.003"]},
                {"technique": "T1204", "subTechniques": []},
            ],
        }
    ]
    assert "category" not in template and "mitreTechniques" not in template


def test_every_tactic_carries_every_technique(platform, pushed):
    """Sigma does not say which technique belongs to which tactic: none is dropped."""

    rule_content = build_rule_content(tags=["attack.persistence", "attack.privilege-escalation", "attack.t1053.005"])

    platform.create_rule(rule_content, "DeviceEvents", RULE_FILE)

    techniques = [{"technique": "T1053", "subTechniques": ["T1053.005"]}]
    assert alert_template(pushed[0])["tactics"] == [
        {"tactic": "Persistence", "techniques": techniques},
        {"tactic": "PrivilegeEscalation", "techniques": techniques},
    ]


def test_a_rule_without_attack_tags_has_no_tactics(platform, pushed):
    platform.create_rule(build_rule_content(tags=["detection.threat-hunting"]), "DeviceEvents", RULE_FILE)

    assert alert_template(pushed[0])["tactics"] == []


# Change detection


def deployed_rule(payload, **changes):
    """The rule as Graph returns it: every property, unset ones empty"""

    rule = copy.deepcopy(payload)
    rule.update(
        {
            "id": "planet-express-rule",
            "createdBy": "hermes@planet-express.local",
            "lastModifiedDateTime": "3026-11-08T10:00:00Z",
        }
    )
    template = rule["detectionAction"]["alertTemplate"]
    template["recommendedActions"] = ""
    template.setdefault("customDetails", {})
    rule.update(changes)
    return rule


@pytest.fixture
def build_payload(platform, pushed):
    def build(rule_content=None):
        platform.create_rule(rule_content or build_rule_content(), "DeviceEvents", RULE_FILE)
        return pushed.pop()

    return build


def test_a_deployed_rule_as_graph_returns_it_is_unchanged(platform, build_payload):
    payload = build_payload()

    assert platform.rule_differences(deployed_rule(payload), payload) == []


def test_the_same_frequency_spelled_differently_is_unchanged(platform, build_payload):
    payload = build_payload(build_rule_content({"query_period": "24H"}))

    deployed = deployed_rule(payload, schedule={"frequency": "PT24H"})

    assert platform.rule_differences(deployed, payload) == []


def test_tactics_in_another_order_are_unchanged(platform, build_payload):
    payload = build_payload(build_rule_content(tags=["attack.persistence", "attack.privilege-escalation", "attack.t1053"]))
    deployed = deployed_rule(payload)
    deployed["detectionAction"]["alertTemplate"]["tactics"].reverse()

    assert platform.rule_differences(deployed, payload) == []


def test_a_changed_technique_is_detected(platform, build_payload):
    payload = build_payload()
    deployed = deployed_rule(payload)
    deployed["detectionAction"]["alertTemplate"]["tactics"][0]["techniques"] = [{"technique": "T1204"}]

    assert platform.rule_differences(deployed, payload) == ["tactics"]


@pytest.mark.parametrize(
    "changes, difference",
    [
        ({"status": "disabled"}, "status"),
        ({"schedule": {"frequency": "PT3H"}}, "frequency"),
        ({"queryCondition": {"queryText": "DeviceEvents | take 1"}}, "query"),
        ({"displayName": "Anchovy smuggling on Mars"}, "displayName"),
    ],
)
def test_a_changed_setting_is_detected(platform, build_payload, changes, difference):
    payload = build_payload()

    assert platform.rule_differences(deployed_rule(payload, **changes), payload) == [difference]


# Export to the platform


@pytest.fixture
def graph(platform, monkeypatch):
    """Stub the Graph calls of push_detection_rule, recording the writes"""

    calls = {"existing": None, "patch": [], "post": []}
    monkeypatch.setattr("droid.platforms.ms_xdr.time.sleep", lambda seconds: None)
    monkeypatch.setattr(platform, "get_rule", lambda rule_id, tenant_id=None: calls["existing"])

    def fake_patch(url=None, payload=None, tenant_id=None):
        calls["patch"].append(copy.deepcopy(payload))
        return {}, 200

    def fake_post(url=None, payload=None, tenant_id=None):
        calls["post"].append(copy.deepcopy(payload))
        return {}, 201

    monkeypatch.setattr(platform, "_patch", fake_patch)
    monkeypatch.setattr(platform, "_post", fake_post)
    return calls


def push(platform, payload):
    # The class method: build_payload stubs the instance one to capture payloads
    MicrosoftXDRPlatform.push_detection_rule(
        platform,
        alert_rule=payload, rule_content=build_rule_content(), rule_file=RULE_FILE, rule_converted="DeviceEvents"
    )


def test_an_unchanged_rule_is_not_written(platform, build_payload, graph):
    payload = build_payload()
    graph["existing"] = deployed_rule(payload)

    push(platform, payload)

    assert graph["patch"] == [] and graph["post"] == []


def test_a_rule_auto_disabled_by_microsoft_is_left_disabled(platform, build_payload, graph):
    payload = build_payload()
    graph["existing"] = deployed_rule(payload, status="autoDisabled")

    push(platform, payload)

    assert graph["patch"] == []


def test_a_change_to_an_auto_disabled_rule_does_not_re_enable_it(platform, build_payload, graph):
    payload = build_payload()
    graph["existing"] = deployed_rule(
        payload, status="autoDisabled", queryCondition={"queryText": "DeviceEvents | take 1"}
    )

    push(platform, payload)

    assert len(graph["patch"]) == 1
    assert "status" not in graph["patch"][0]


def test_disabling_an_auto_disabled_rule_is_pushed(platform, build_payload, graph):
    payload = build_payload(build_rule_content({"disabled": True}))
    graph["existing"] = deployed_rule(payload, status="autoDisabled")

    push(platform, payload)

    assert graph["patch"][0]["status"] == "disabled"
