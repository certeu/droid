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
