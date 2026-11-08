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


# The technique to tactics mapping of ATT&CK v20, where Defense Evasion is
# split into stealth and defense-impairment
ATTACK_MAPPING = {
    "T1053": ["execution", "persistence", "privilege-escalation"],
    "T1059": ["execution"],
    "T1078": ["stealth", "persistence", "privilege-escalation", "initial-access"],
    "T1204": ["execution"],
    "T1562": ["defense-impairment"],
}


@pytest.fixture(autouse=True)
def attack_mapping(monkeypatch):
    """ATT&CK data without downloading it from MITRE"""
    from sigma.data import mitre_attack

    monkeypatch.setattr(mitre_attack, "mitre_attack_techniques_tactics_mapping", ATTACK_MAPPING, raising=False)


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

    assert alert_template(pushed[0])["entityMappings"] == {"hosts": [{"deviceIdColumn": "DeviceId"}]}


def test_a_rule_without_entity_mappings_maps_its_device(platform, pushed):
    """Microsoft derives no entity: without one, alerts correlate into
    incidents poorly. The device is what impactedAssets mapped by default."""

    platform.create_rule(build_rule_content(), "DeviceEvents", RULE_FILE)

    assert alert_template(pushed[0])["entityMappings"] == {"hosts": [{"deviceIdColumn": "DeviceId"}]}


def test_entity_mappings_replace_the_default_device(platform, pushed):
    custom = {
        "xdr_entity_mappings": [
            {"entity_type": "accounts", "field_mappings": [{"identifier": "upnColumn", "column_name": "AccountUpn"}]}
        ]
    }

    platform.create_rule(build_rule_content(custom), "DeviceEvents", RULE_FILE)

    assert alert_template(pushed[0])["entityMappings"] == {"accounts": [{"upnColumn": "AccountUpn"}]}


def test_a_deployed_rule_without_entities_is_updated(platform, build_payload):
    """Rules exported without entities must get the default device mapped"""

    payload = build_payload()
    deployed = deployed_rule(payload)
    deployed["detectionAction"]["alertTemplate"]["entityMappings"] = {"hosts": [], "accounts": []}

    assert platform.rule_differences(deployed, payload) == ["entityMappings"]


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
    [("0", "PT0S"), ("1h", "PT1H"), ("3H", "PT3H"), ("12H", "PT12H"), ("24H", "P1D")],
)
def test_the_query_period_is_pushed_as_a_frequency(platform, pushed, query_period, frequency):
    platform.create_rule(build_rule_content({"query_period": query_period}), "DeviceEvents", RULE_FILE)

    assert pushed[0]["schedule"] == {"frequency": frequency}


def test_the_configured_query_period_applies_by_default(platform, pushed):
    platform.create_rule(build_rule_content(), "DeviceEvents", RULE_FILE)

    assert pushed[0]["schedule"] == {"frequency": "PT1H"}


def test_a_rule_query_period_overrides_the_configuration(pushed, monkeypatch):
    platform = MicrosoftXDRPlatform(dict(XDR_PARAMETERS, query_period="0"), LOGGER_PARAM)
    monkeypatch.setattr(platform, "push_detection_rule", lambda alert_rule=None, **kwargs: pushed.append(alert_rule))

    platform.create_rule(build_rule_content({"query_period": "12H"}), "DeviceEvents", RULE_FILE)

    assert pushed[0]["schedule"] == {"frequency": "PT12H"}


def test_a_continuous_rule_as_graph_returns_it_is_unchanged(platform, pushed):
    """Graph may spell the zero duration of a continuous rule another way"""

    platform.create_rule(build_rule_content({"query_period": "0"}), "DeviceEvents", RULE_FILE)
    deployed = copy.deepcopy(pushed[0])
    deployed["schedule"] = {"frequency": "PT0M"}

    assert platform.rule_differences(deployed, pushed[0]) == []


@pytest.mark.parametrize("query_period", ["2H", "PT1H"])
def test_an_unknown_query_period_is_an_error(platform, pushed, query_period):

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


def test_a_technique_goes_under_the_tagged_tactics_it_belongs_to(platform, pushed):
    """Graph refuses a technique under a tactic it does not belong to"""

    rule_content = build_rule_content(
        tags=["attack.persistence", "attack.privilege-escalation", "attack.command-and-control", "attack.t1053.005"]
    )

    platform.create_rule(rule_content, "DeviceEvents", RULE_FILE)

    techniques = [{"technique": "T1053", "subTechniques": ["T1053.005"]}]
    assert alert_template(pushed[0])["tactics"] == [
        {"tactic": "Persistence", "techniques": techniques},
        {"tactic": "PrivilegeEscalation", "techniques": techniques},
        {"tactic": "CommandAndControl", "techniques": []},
    ]


def test_a_technique_of_no_tagged_tactic_goes_under_its_own(platform, pushed):
    rule_content = build_rule_content(tags=["attack.initial-access", "attack.t1059.001"])

    platform.create_rule(rule_content, "DeviceEvents", RULE_FILE)

    assert alert_template(pushed[0])["tactics"] == [
        {"tactic": "InitialAccess", "techniques": []},
        {"tactic": "Execution", "techniques": [{"technique": "T1059", "subTechniques": ["T1059.001"]}]},
    ]


@pytest.mark.parametrize("technique", ["t1078", "t1562"])
def test_defense_evasion_matches_the_tactics_attack_split_it_into(platform, pushed, technique):
    """ATT&CK v18 split Defense Evasion into Stealth and Defense Impairment,
    which Sigma tags and Microsoft still call Defense Evasion"""

    platform.create_rule(build_rule_content(tags=["attack.defense-evasion", f"attack.{technique}"]), "DeviceEvents", RULE_FILE)

    assert alert_template(pushed[0])["tactics"] == [
        {"tactic": "DefenseEvasion", "techniques": [{"technique": technique.upper(), "subTechniques": []}]}
    ]


def test_without_attack_data_techniques_go_under_the_tagged_tactics(platform, pushed, monkeypatch):
    """ATT&CK is downloaded: offline, Graph refusing a pair is dealt with on push"""

    def unavailable(technique, rule_file):
        return None

    monkeypatch.setattr(platform, "_attack_tactics_of", unavailable)

    platform.create_rule(build_rule_content(tags=["attack.initial-access", "attack.t1059"]), "DeviceEvents", RULE_FILE)

    assert alert_template(pushed[0])["tactics"] == [
        {"tactic": "InitialAccess", "techniques": [{"technique": "T1059", "subTechniques": []}]}
    ]


def test_a_rule_without_attack_tags_has_no_tactics(platform, pushed):
    platform.create_rule(build_rule_content(tags=["detection.threat-hunting"]), "DeviceEvents", RULE_FILE)

    assert alert_template(pushed[0])["tactics"] == []



# Automated actions


def automated_actions(payload):
    """The non-empty collections of the automatedActions pushed"""
    return {collection: entries for collection, entries in payload["detectionAction"]["automatedActions"].items() if entries}


def test_actions_are_pushed_as_automated_actions(platform, pushed):
    custom = {
        "actions": [
            {"action": "isolateDevice", "isolationType": "selective"},
            {"action": "disableUser", "identifier": "initiatingProcessAccountSid"},
            {"action": "stopAndQuarantineFile", "identifier": "sha1"},
            {"action": "blockFile", "identifier": ["sha1", "sha256"], "deviceGroupNames": "Hermes desks"},
        ]
    }

    platform.create_rule(build_rule_content(custom), "DeviceEvents", RULE_FILE)

    assert "responseActions" not in pushed[0]["detectionAction"]
    assert automated_actions(pushed[0]) == {
        "isolateDevices": [{"deviceIdColumn": "DeviceId", "isolationType": "selective"}],
        "disableUsers": [{"accountSidColumn": "InitiatingProcessAccountSid"}],
        "stopAndQuarantineFiles": [{"sha1Column": "SHA1", "deviceIdColumn": "DeviceId"}],
        "blockFiles": [{"sha1Column": "SHA1", "sha256Column": "SHA256", "deviceGroupNames": ["Hermes desks"]}],
    }


def test_a_rule_without_actions_clears_them(platform, pushed):
    """Every collection is sent, so an action dropped from a rule is dropped
    from the platform rather than left running."""

    platform.create_rule(build_rule_content(), "DeviceEvents", RULE_FILE)

    actions = pushed[0]["detectionAction"]["automatedActions"]
    assert actions["isolateDevices"] == [] and automated_actions(pushed[0]) == {}


@pytest.mark.parametrize(
    "action, expected",
    [
        ({"action": "disableUser", "identifier": "onPremSid"}, {"disableUsers": [{"accountSidColumn": "OnPremSid"}]}),
        (
            {"action": "forceUserPasswordReset", "identifier": "requestAccountSid"},
            {"forceUserPasswordResets": [{"accountSidColumn": "RequestAccountSid"}]},
        ),
        (
            {"action": "markUserAsCompromised", "identifier": "servicePrincipalId"},
            {"markUsersAsCompromised": [{"accountObjectIdColumn": "ServicePrincipalId"}]},
        ),
        (
            {"action": "markUserAsCompromised", "identifier": "recipientObjectId"},
            {"markUsersAsCompromised": [{"accountObjectIdColumn": "RecipientObjectId"}]},
        ),
        (
            {"action": "stopAndQuarantineFile", "identifier": ["deviceId", "sha1"]},
            {"stopAndQuarantineFiles": [{"deviceIdColumn": "DeviceId", "sha1Column": "SHA1"}]},
        ),
    ],
    ids=["onPremSid", "requestAccountSid", "servicePrincipalId", "recipientObjectId", "deviceId"],
)
def test_every_identifier_the_removed_response_actions_took_still_deploys(platform, action, expected):
    """Rules written for responseActions must not break on upgrade"""

    actions = platform.parse_actions([action], rule_file=RULE_FILE)

    assert {collection: entries for collection, entries in actions.items() if entries} == expected


def test_an_unknown_action_is_skipped(platform, pushed):
    custom = {"actions": [{"action": "launchNibbler"}, {"action": "runAntivirusScan"}]}

    platform.create_rule(build_rule_content(custom), "DeviceEvents", RULE_FILE)

    assert automated_actions(pushed[0]) == {"runAntivirusScans": [{"deviceIdColumn": "DeviceId"}]}


@pytest.mark.parametrize(
    "action",
    [
        {"identifier": "accountSid"},
        {"action": "disableUser"},
        {"action": "disableUser", "identifier": "accountObjectId"},
        {"action": "isolateDevice"},
        {"action": "blockFile", "identifier": ["sha1", "initiatingProcessSHA1"]},
    ],
    ids=["no-action-name", "no-identifier", "wrong-identifier", "no-isolation-type", "same-column-twice"],
)
def test_an_invalid_action_is_an_error(platform, action):
    with pytest.raises(ValueError):
        platform.parse_actions([action], rule_file=RULE_FILE)


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


def test_automated_actions_as_graph_returns_them_are_unchanged(platform, build_payload):
    payload = build_payload(build_rule_content({"actions": [{"action": "isolateDevice", "isolationType": "full"}]}))
    deployed = deployed_rule(payload)
    actions = deployed["detectionAction"]["automatedActions"]
    actions["@odata.type"] = "#microsoft.graph.security.automatedActionSet"
    actions["hardDeleteEmails"] = []
    actions["isolateDevices"][0]["@odata.type"] = "#microsoft.graph.security.isolateDeviceAction"

    assert platform.rule_differences(deployed, payload) == []


def test_an_email_action_set_on_the_portal_is_not_a_change(platform, build_payload):
    """droid has no custom.actions for the email actions: one set on the
    portal must not have every export update the rule."""

    payload = build_payload()
    deployed = deployed_rule(payload)
    deployed["detectionAction"]["automatedActions"]["softDeleteEmails"] = [
        {"networkMessageIdColumn": "NetworkMessageId", "recipientColumn": "RecipientEmailAddress"}
    ]

    assert platform.rule_differences(deployed, payload) == []


def test_entity_mappings_annotated_by_graph_are_unchanged(platform, build_payload):
    custom = {
        "xdr_entity_mappings": [
            {"entity_type": "hosts", "field_mappings": [{"identifier": "deviceIdColumn", "column_name": "DeviceId"}]}
        ]
    }
    payload = build_payload(build_rule_content(custom))
    deployed = deployed_rule(payload)
    mappings = deployed["detectionAction"]["alertTemplate"]["entityMappings"]
    mappings["@odata.type"] = "#microsoft.graph.security.entityMappingConfiguration"
    mappings["hosts"][0]["@odata.type"] = "#microsoft.graph.security.hostEntityMapping"

    assert platform.rule_differences(deployed, payload) == []


def test_a_changed_action_is_detected(platform, build_payload):
    payload = build_payload(build_rule_content({"actions": [{"action": "isolateDevice", "isolationType": "full"}]}))
    deployed = deployed_rule(payload)
    deployed["detectionAction"]["automatedActions"]["isolateDevices"][0]["isolationType"] = "selective"

    assert platform.rule_differences(deployed, payload) == ["automatedActions"]


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


def test_techniques_graph_refuses_are_dropped_and_the_rule_deployed(platform, build_payload, monkeypatch):
    """Microsoft validates against an older ATT&CK than droid's: the rule is
    deployed without the pairs it refuses rather than not at all."""

    payload = build_payload(build_rule_content(tags=["attack.initial-access", "attack.t1078", "attack.t1059"]))
    monkeypatch.setattr("droid.platforms.ms_xdr.time.sleep", lambda seconds: None)
    monkeypatch.setattr(platform, "get_rule", lambda rule_id, tenant_id=None: None)
    sent = []
    refusal = {
        "error": {
            "code": "BadRequest",
            "message": "MITRE properties are invalid: Technique 'T1078' is not a valid parent technique under tactic 'InitialAccess'.",
        }
    }

    def fake_post(url=None, payload=None, tenant_id=None):
        sent.append(copy.deepcopy(payload))
        return (refusal, 400) if len(sent) == 1 else ({}, 201)

    monkeypatch.setattr(platform, "_post", fake_post)

    push(platform, payload)

    assert len(sent) == 2
    assert sent[1]["detectionAction"]["alertTemplate"]["tactics"] == [
        {"tactic": "InitialAccess", "techniques": []},
        {"tactic": "Execution", "techniques": [{"technique": "T1059", "subTechniques": []}]},
    ]


def test_another_bad_request_is_not_retried(platform, build_payload, monkeypatch):
    payload = build_payload()
    monkeypatch.setattr(platform, "get_rule", lambda rule_id, tenant_id=None: None)
    sent = []

    def fake_post(url=None, payload=None, tenant_id=None):
        sent.append(payload)
        return {"error": {"code": "BadRequest", "message": "Invalid query"}}, 400

    monkeypatch.setattr(platform, "_post", fake_post)

    with pytest.raises(Exception):
        push(platform, payload)
    assert len(sent) == 1


def test_a_new_rule_is_created_with_the_sigma_id(platform, build_payload, graph):
    """Graph v1.0 has the client choose the id of a rule it creates."""

    payload = build_payload()

    push(platform, payload)

    assert graph["post"][0]["id"] == build_rule_content()["id"]


def test_an_update_does_not_change_the_rule_id(platform, build_payload, graph):
    """A rule created on beta has an id Graph chose, which stays its id."""

    payload = build_payload()
    graph["existing"] = deployed_rule(payload, id="1255", status="disabled")

    push(platform, payload)

    assert "id" not in graph["patch"][0]
    assert graph["patch"][0]["status"] == "enabled"


def test_rules_are_managed_on_graph_v1(platform):
    assert platform._api_base_url == "https://graph.microsoft.com/v1.0"
