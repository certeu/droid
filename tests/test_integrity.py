"""
Tests of the integrity check
"""

import pytest

from types import SimpleNamespace

from droid.integrity import integrity_rule

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
        "detection": {},
    }
    if removed:
        rule_content["custom"] = {"removed": True}
    return rule_content


def build_xdr_rule(query="the deployed query", description="A rule", enabled=True):
    return {
        "queryCondition": {"queryText": query},
        "detectionAction": {"alertTemplate": {"description": description}},
        "isEnabled": enabled,
    }


class FakeXDRPlatform:
    """Minimal stand-in for MicrosoftXDRPlatform"""

    def __init__(self, rules=None, export_list=None):
        # rules: {tenant_id or None: saved_search or None}
        self._rules = rules if rules is not None else {}
        self._export_list = export_list or {}
        self._convert_rule_callback = None

    def get_rule(self, rule_id, tenant_id=None):
        return self._rules.get(tenant_id)

    def get_export_list_mssp(self):
        return self._export_list


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


class FakeElasticPlatform:
    """Minimal stand-in for ElasticPlatform"""

    def __init__(self, saved_search=None):
        self._saved_search = saved_search

    def get_rule(self, rule_id):
        return self._saved_search


def build_splunk_rule(search="the deployed query", description="A rule", disabled="0"):
    return {"search": search, "description": description, "disabled": disabled}


def build_sentinel_rule(query="the deployed query", description="A rule", enabled=True):
    return SimpleNamespace(
        name=RULE_ID, description=description, query=query, enabled=enabled
    )


def build_elastic_rule(query="the deployed query", description="A rule"):
    return {"name": RULE_ID, "description": description, "query": query}


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


def test_elastic_removed_rule_still_on_the_platform():
    """A removed rule still deployed on Elastic is still an integrity error"""
    platform = FakeElasticPlatform(build_elastic_rule(query="a stale query"))
    error = run_integrity(
        platform, build_rule_content(removed=True), "the new query",
        platform_name="esql"
    )
    assert error


def test_elastic_removed_rule_absent_from_the_platform():
    """A removed rule already deleted from Elastic is not an integrity error"""
    platform = FakeElasticPlatform(None)
    error = run_integrity(
        platform, build_rule_content(removed=True), "the new query",
        platform_name="esql"
    )
    assert not error


def test_elastic_rule_matching_the_platform():
    """A rule matching Elastic is not an integrity error"""
    platform = FakeElasticPlatform(build_elastic_rule(query="the new query"))
    error = run_integrity(
        platform, build_rule_content(), "the new query", platform_name="esql"
    )
    assert not error
