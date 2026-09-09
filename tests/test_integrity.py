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


def run_integrity(platform, rule_content, rule_converted, mssp=False):
    parameters = SimpleNamespace(
        platform="microsoft_xdr", mssp=mssp, sentinel_xdr=False
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


def test_xdr_mssp_rule_not_matching_on_one_tenant():
    """A rule differing on a single tenant is an integrity error"""
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
