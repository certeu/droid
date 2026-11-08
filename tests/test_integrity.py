"""
Tests of the integrity check
"""

import pytest

from types import SimpleNamespace

from droid.integrity import integrity_rule
from droid.platforms.ms_xdr import MicrosoftXDRPlatform

LOGGER_PARAM = {
    "debug_mode": False,
    "json_enabled": False,
    "json_stdout": False,
    "log_file": None,
}

RULE_ID = "5f5d1b1e-9f2a-4a2b-8e4e-1c2d3e4f5a6b"


def build_rule_content(removed=False, description="A rule"):
    rule_content = {
        "id": RULE_ID,
        "title": "A rule",
        "description": description,
        "level": "medium",
        "tags": ["attack.execution", "attack.t1059.001"],
        "detection": {},
    }
    if removed:
        rule_content["custom"] = {"removed": True}
    return rule_content


XDR_PARAMETERS = {
    "query_period": "1h",
    "tenant_id": "tenant-planet-express",
    "search_auth": "default",
    "export_auth": "default",
}


class FakeXDRPlatform(MicrosoftXDRPlatform):
    """MicrosoftXDRPlatform building and comparing rules for real, its Graph calls stubbed"""

    def __init__(self, rules=None, export_list=None):
        super().__init__(dict(XDR_PARAMETERS), LOGGER_PARAM)
        # rules: {tenant_id or None: saved_search or None}
        self._rules = rules if rules is not None else {}
        self._export_list = export_list or {}

    def get_rule(self, rule_id, tenant_id=None):
        return self._rules.get(tenant_id)

    def get_export_list_mssp(self):
        return self._export_list


def build_xdr_rule(query="the deployed query", description="A rule", status="enabled", rule_content=None):
    """The rule as Graph returns it once export deployed it"""
    rule = FakeXDRPlatform().build_alert_rule(rule_content or build_rule_content(description=description), query, "a_rule.yml")
    rule.update(id="1255", status=status, createdBy="hermes@planet-express.local")
    rule["detectionAction"]["alertTemplate"]["recommendedActions"] = ""
    return rule


class FakeSplunkPlatform:
    """Minimal stand-in for SplunkPlatform"""

    def __init__(self, saved_search=None):
        self._saved_search = saved_search

    def search_savedsearch(self, rule_content):
        return self._saved_search


class FakeSentinelPlatform:
    """Minimal stand-in for SentinelPlatform"""

    def __init__(self, saved_search=None):
        self._saved_search = saved_search

    def get_rule(self, rule_content, rule_file):
        return self._saved_search


def build_splunk_rule(search="the deployed query", description="A rule", disabled="0"):
    return {"search": search, "description": description, "disabled": disabled}


def build_sentinel_rule(query="the deployed query", description="A rule", enabled=True):
    return SimpleNamespace(
        name=RULE_ID, description=description, query=query, enabled=enabled
    )


def run_integrity(platform, rule_content, rule_converted, mssp=False, platform_name="microsoft_xdr"):
    parameters = SimpleNamespace(
        platform=platform_name, mssp=mssp, sentinel_xdr=False
    )
    return integrity_rule(
        parameters, rule_converted, rule_content, platform,
        "a_rule.yml", False, LOGGER_PARAM
    )


def test_xdr_removed_rule_still_on_the_platform():
    """A removed rule not yet deleted on the platform is not an integrity error"""
    platform = FakeXDRPlatform({None: build_xdr_rule(query="a stale query")})
    error = run_integrity(platform, build_rule_content(removed=True), "the new query")
    assert not error


def test_xdr_removed_rule_absent_from_the_platform():
    """A removed rule already deleted on the platform is not an integrity error"""
    platform = FakeXDRPlatform({None: None})
    error = run_integrity(platform, build_rule_content(removed=True), "the new query")
    assert not error


def test_xdr_rule_absent_from_the_platform():
    """A rule missing from the platform is an integrity error"""
    platform = FakeXDRPlatform({None: None})
    error = run_integrity(platform, build_rule_content(), "the new query")
    assert error


def test_xdr_rule_not_matching_the_platform():
    """A rule differing from the platform is an integrity error"""
    platform = FakeXDRPlatform({None: build_xdr_rule(query="a stale query")})
    error = run_integrity(platform, build_rule_content(), "the new query")
    assert error


def test_xdr_rule_matching_the_platform():
    """A rule matching the platform is not an integrity error"""
    platform = FakeXDRPlatform({None: build_xdr_rule(query="the new query")})
    error = run_integrity(platform, build_rule_content(), "the new query")
    assert not error


def test_xdr_rule_auto_disabled_on_the_platform():
    """Microsoft turns off a rule that keeps failing: it no longer detects
    anything, which integrity must report."""

    platform = FakeXDRPlatform({None: build_xdr_rule(query="the new query", status="autoDisabled")})
    assert run_integrity(platform, build_rule_content(), "the new query")


def test_xdr_rule_disabled_as_expected():
    platform = FakeXDRPlatform({None: build_xdr_rule(query="the new query", status="disabled")})
    rule_content = build_rule_content()
    rule_content["custom"] = {"disabled": True}
    assert not run_integrity(platform, rule_content, "the new query")


@pytest.mark.parametrize(
    "drift",
    [
        lambda rule: rule["schedule"].update(frequency="P1D"),
        lambda rule: rule["detectionAction"]["alertTemplate"].update(severity="low"),
        lambda rule: rule["detectionAction"]["alertTemplate"].update(title="A rule, edited on the portal"),
        lambda rule: rule["detectionAction"]["alertTemplate"].update(tactics=[]),
        lambda rule: rule["detectionAction"]["automatedActions"].update(isolateDevices=[{"deviceIdColumn": "DeviceId"}]),
        lambda rule: rule.update(displayName="A rule"),
    ],
    ids=["frequency", "severity", "title", "tactics", "actions", "display-name"],
)
def test_xdr_rule_drifting_from_export_on_any_setting(drift):
    """Integrity checks every setting export deploys, not only the query"""
    deployed = build_xdr_rule(query="the new query")
    drift(deployed)
    platform = FakeXDRPlatform({None: deployed})
    assert run_integrity(platform, build_rule_content(), "the new query")


def test_xdr_rule_with_entity_mappings_matching_the_platform():
    rule_content = build_rule_content()
    rule_content["custom"] = {
        "xdr_entity_mappings": [
            {"entity_type": "hosts", "field_mappings": [{"identifier": "deviceIdColumn", "column_name": "DeviceId"}]}
        ]
    }
    deployed = build_xdr_rule(query="the new query", rule_content=rule_content)
    # Graph fills in every column of an entity, unset ones empty
    deployed["detectionAction"]["alertTemplate"]["entityMappings"]["hosts"][0]["nameColumn"] = ""
    platform = FakeXDRPlatform({None: deployed})
    assert not run_integrity(platform, rule_content, "the new query")


def test_xdr_rule_that_cannot_be_built_is_an_integrity_error():
    """A rule export would refuse cannot match the platform"""
    rule_content = build_rule_content()
    platform = FakeXDRPlatform({None: build_xdr_rule(query="the new query")})
    rule_content["custom"] = {"query_period": "2H"}
    assert run_integrity(platform, rule_content, "the new query")


def test_xdr_mssp_removed_rule_still_on_the_platform():
    """A removed rule not yet deleted on one tenant is not an integrity error"""
    platform = FakeXDRPlatform(
        rules={
            "tenant-a": build_xdr_rule(query="a stale query"),
            "tenant-b": None,
        },
        export_list={
            "group-a": {"tenant_id": "tenant-a"},
            "group-b": {"tenant_id": "tenant-b"},
        },
    )
    error = run_integrity(
        platform, build_rule_content(removed=True), "the new query", mssp=True
    )
    assert not error


def test_xdr_mssp_removed_rule_absent_from_the_platform():
    """A removed rule already deleted on every tenant is not an integrity error"""
    platform = FakeXDRPlatform(
        rules={"tenant-a": None, "tenant-b": None},
        export_list={
            "group-a": {"tenant_id": "tenant-a"},
            "group-b": {"tenant_id": "tenant-b"},
        },
    )
    error = run_integrity(
        platform, build_rule_content(removed=True), "the new query", mssp=True
    )
    assert not error


def test_xdr_mssp_rule_absent_from_one_tenant():
    """A rule missing from a single tenant is an integrity error"""
    platform = FakeXDRPlatform(
        rules={
            "tenant-a": build_xdr_rule(query="the new query"),
            "tenant-b": None,
        },
        export_list={
            "group-a": {"tenant_id": "tenant-a"},
            "group-b": {"tenant_id": "tenant-b"},
        },
    )
    error = run_integrity(platform, build_rule_content(), "the new query", mssp=True)
    assert error


def test_xdr_mssp_rule_matching_every_tenant():
    """A rule matching on every tenant is not an integrity error"""
    platform = FakeXDRPlatform(
        rules={
            "tenant-a": build_xdr_rule(query="the new query"),
            "tenant-b": build_xdr_rule(query="the new query"),
        },
        export_list={
            "group-a": {"tenant_id": "tenant-a"},
            "group-b": {"tenant_id": "tenant-b"},
        },
    )
    error = run_integrity(platform, build_rule_content(), "the new query", mssp=True)
    assert not error


def test_xdr_mssp_rule_not_matching_on_one_tenant():
    """A rule differing on a tenant is an integrity error, even when a later tenant matches"""
    platform = FakeXDRPlatform(
        rules={
            "tenant-a": build_xdr_rule(query="a stale query"),
            "tenant-b": build_xdr_rule(query="the new query"),
        },
        export_list={
            "group-a": {"tenant_id": "tenant-a"},
            "group-b": {"tenant_id": "tenant-b"},
        },
    )
    error = run_integrity(platform, build_rule_content(), "the new query", mssp=True)
    assert error


# The deletion delay is tolerated on Microsoft XDR only, the other platforms
# must keep reporting a removed rule that is still deployed


def test_splunk_removed_rule_still_on_the_platform():
    """A removed rule still deployed on Splunk is still an integrity error"""
    platform = FakeSplunkPlatform(build_splunk_rule(search="a stale query"))
    error = run_integrity(
        platform, build_rule_content(removed=True), "the new query",
        platform_name="splunk"
    )
    assert error


def test_splunk_removed_rule_absent_from_the_platform():
    """A removed rule already deleted from Splunk is not an integrity error"""
    platform = FakeSplunkPlatform(None)
    error = run_integrity(
        platform, build_rule_content(removed=True), "the new query",
        platform_name="splunk"
    )
    assert not error


def test_splunk_rule_matching_the_platform():
    """A rule matching Splunk is not an integrity error"""
    platform = FakeSplunkPlatform(build_splunk_rule(search="the new query"))
    error = run_integrity(
        platform, build_rule_content(), "the new query", platform_name="splunk"
    )
    assert not error


def test_sentinel_removed_rule_still_on_the_platform():
    """A removed rule still deployed on Sentinel is still an integrity error"""
    platform = FakeSentinelPlatform(build_sentinel_rule(query="a stale query"))
    error = run_integrity(
        platform, build_rule_content(removed=True), "the new query",
        platform_name="microsoft_sentinel"
    )
    assert error


def test_sentinel_removed_rule_absent_from_the_platform():
    """A removed rule already deleted from Sentinel is not an integrity error"""
    platform = FakeSentinelPlatform(None)
    error = run_integrity(
        platform, build_rule_content(removed=True), "the new query",
        platform_name="microsoft_sentinel"
    )
    assert not error


def test_sentinel_rule_matching_the_platform():
    """A rule matching Sentinel is not an integrity error"""
    platform = FakeSentinelPlatform(build_sentinel_rule(query="the new query"))
    error = run_integrity(
        platform, build_rule_content(), "the new query",
        platform_name="microsoft_sentinel"
    )
    assert not error


ELASTIC_PARAMETERS = {
    "kibana_url": "https://kibana.planet-express.local",
    "elastic_hosts": ["https://elastic.planet-express.local"],
    "elastic_tls_verify": True,
    "auth_method": "basic",
    "schedule_interval": 5,
    "schedule_interval_unit": "m",
    "actions": {"alerts_index": {"type": "index", "connector_id": "planet-express-alerts"}},
}

ELASTIC_QUERY = "FROM logs-* METADATA _id, _index, _version | WHERE true"


def build_elastic_rule_content(**custom):
    rule_content = {
        **build_rule_content(),
        "level": "high",
        "author": "Hermes Conrad",
        "tags": ["attack.t1078", "planet-express"],
    }
    if custom:
        rule_content["custom"] = custom
    return rule_content


def elastic_platform(deployed):
    """A real Elastic platform reading `deployed` as the rule on Kibana"""
    from droid.platforms.elastic import ElasticPlatform

    platform = ElasticPlatform(dict(ELASTIC_PARAMETERS), LOGGER_PARAM, "esql")
    platform.get_rule = lambda rule_id: deployed
    return platform


def deployed_as_exported(rule_content=None, query=ELASTIC_QUERY, **changes):
    """The rule export deployed, as Kibana returns it, with changes made since"""
    platform = elastic_platform(None)
    rule = platform.build_rule(rule_content or build_elastic_rule_content(), query, "a_rule.yml")
    rule["actions"] = [{**action, "uuid": "kibana-gives-each-action-one"} for action in rule["actions"]]
    rule["revision"] = 3
    return {**rule, **changes}


def run_elastic_integrity(deployed, rule_content=None, query=ELASTIC_QUERY):
    return run_integrity(
        elastic_platform(deployed), rule_content or build_elastic_rule_content(), query, platform_name="esql"
    )


def test_elastic_rule_matching_the_platform():
    """A rule matching Elastic is not an integrity error"""
    assert not run_elastic_integrity(deployed_as_exported())


def test_elastic_removed_rule_still_on_the_platform():
    """A removed rule still deployed on Elastic is still an integrity error"""
    assert run_elastic_integrity(deployed_as_exported(), build_elastic_rule_content(removed=True))


def test_elastic_removed_rule_absent_from_the_platform():
    """A removed rule already deleted from Elastic is not an integrity error"""
    assert not run_elastic_integrity(None, build_elastic_rule_content(removed=True))


def test_elastic_rule_absent_from_the_platform():
    assert run_elastic_integrity(None)


def test_elastic_rule_kibana_cannot_show_is_an_error():
    """Integrity that cannot read the rule has checked nothing"""
    platform = elastic_platform(None)

    def refused(rule_id):
        raise Exception('{"message": "Unauthorized to get a siem.esqlRule rule"}')

    platform.get_rule = refused

    assert run_integrity(platform, build_elastic_rule_content(), ELASTIC_QUERY, platform_name="esql")


def test_elastic_rule_disabled_but_enabled_on_the_platform():
    """A rule marked disabled must not be running on Elastic"""
    assert run_elastic_integrity(deployed_as_exported(enabled=True), build_elastic_rule_content(disabled=True))


def test_elastic_rule_disabled_on_the_platform():
    """A rule not marked disabled must be running on Elastic"""
    assert run_elastic_integrity(deployed_as_exported(enabled=False))


def test_elastic_rule_disabled_as_expected():
    rule_content = build_elastic_rule_content(disabled=True)

    assert not run_elastic_integrity(deployed_as_exported(rule_content), rule_content)


@pytest.mark.parametrize(
    "field, value",
    [
        ("query", "FROM logs-* METADATA _id, _index, _version | WHERE false"),
        ("description", "Changed in Kibana"),
        ("name", "Renamed in Kibana"),
        ("severity", "critical"),
        ("risk_score", 99),
        ("interval", "1h"),
        ("from", "now-1m"),
        ("tags", ["tampered"]),
        ("threat", []),
        ("actions", []),
        ("max_signals", 1000),
        ("alert_suppression", {"group_by": ["host.name"], "missing_fields_strategy": "suppress"}),
        ("building_block_type", "default"),
    ],
)
def test_elastic_rule_changed_on_the_platform(field, value):
    """Anything export sets and Kibana now holds differently is drift"""
    assert run_elastic_integrity(deployed_as_exported(**{field: value}))


def test_elastic_eql_rule_reading_another_index():
    from droid.platforms.elastic import ElasticPlatform

    platform = ElasticPlatform(dict(ELASTIC_PARAMETERS), LOGGER_PARAM, "eql")
    platform._index_name = ["logs-vault-*"]
    deployed = platform.build_rule(build_elastic_rule_content(), "any where true", "a_rule.yml")
    platform.get_rule = lambda rule_id: {**deployed, "index": ["tampered-*"]}

    assert run_integrity(platform, build_elastic_rule_content(), "any where true", platform_name="eql")


def test_elastic_metadata_added_on_export_is_not_a_difference():
    """Export adds the METADATA clause Elastic needs to deduplicate alerts"""
    converted = "FROM logs-* | WHERE true"

    assert not run_elastic_integrity(deployed_as_exported(query=converted), query=converted)
