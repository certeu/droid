"""
Tests that export failures are propagated to the caller

A failure returned by the platform API (HTTP 400/403) must raise so that
export_rule() flags the error and droid exits with a non-zero code.
"""

import time

import pytest

from droid.export import export_rule
from droid.platforms.ms_xdr import MicrosoftXDRPlatform

LOGGER_PARAM = {
    "debug_mode": False,
    "json_enabled": False,
    "json_stdout": False,
    "log_file": None,
}

RULE_FILE = "rules/sigma/delivery/anchovy_smuggling_on_neptune.yml"

RULE_CONTENT = {
    "id": "0c1b1b1a-0000-0000-0000-0000deadbeef",
    "title": "Anchovy smuggling",
    "description": "Detects anchovies being delivered to Neptune",
    "level": "medium",
    "tags": ["attack.execution"],
}

RULE_CONVERTED = "DeviceNetworkEvents | where RemoteUrl has 'panucci'"

BAD_REQUEST = (
    {"error": {"code": "BadRequest", "message": "Invalid query"}},
    400,
)


def build_platform(export_mssp: bool):
    parameters = {
        "query_period": "24H",
        "search_auth": "app",
        "export_auth": "app",
        "tenant_id": "tenant-new-new-york",
        "client_id": "bender-bending-rodriguez",
        "client_secret": "shiny-metal-secret",
        "export_list_mssp": {
            "group1": {"tenant_id": "tenant-planet-express", "customer_name": "Planet Express"},
            "group2": {"tenant_id": "tenant-panucci", "customer_name": "Panucci's Pizza"},
        },
    }
    return MicrosoftXDRPlatform(parameters, LOGGER_PARAM, export_mssp=export_mssp)


@pytest.fixture
def xdr_bad_request(monkeypatch):
    """Platform factory whose Graph calls always answer 400 Bad Request."""

    def _factory(export_mssp):
        platform = build_platform(export_mssp)
        # No existing rule -> create path, which answers 400
        monkeypatch.setattr(platform, "_get", lambda *a, **kw: ({"value": []}, 200))
        monkeypatch.setattr(platform, "_post", lambda *a, **kw: BAD_REQUEST)
        monkeypatch.setattr(platform, "_patch", lambda *a, **kw: BAD_REQUEST)
        return platform

    return _factory


@pytest.mark.parametrize("export_mssp", [False, True])
def test_xdr_create_rule_raises_on_bad_request(xdr_bad_request, export_mssp):
    """A 400 from Graph must raise instead of silently returning"""
    platform = xdr_bad_request(export_mssp)

    with pytest.raises(Exception):
        platform.create_rule(RULE_CONTENT, RULE_CONVERTED, RULE_FILE)


@pytest.mark.parametrize("export_mssp", [False, True])
def test_xdr_create_rule_succeeds_on_created(monkeypatch, export_mssp):
    """A 201 from Graph must not raise"""
    platform = build_platform(export_mssp)
    monkeypatch.setattr(platform, "_get", lambda *a, **kw: ({"value": []}, 200))
    monkeypatch.setattr(platform, "_post", lambda *a, **kw: ({"id": "rule-anchovy"}, 201))
    monkeypatch.setattr(time, "sleep", lambda *a: None)

    error = export_rule(
        parameters={},
        rule_content=RULE_CONTENT,
        rule_converted=RULE_CONVERTED,
        platform=platform,
        rule_file=RULE_FILE,
        error=False,
        logger_param=LOGGER_PARAM,
    )

    assert error is False


def test_xdr_mssp_partial_failure_flags_error(monkeypatch):
    """One failing tenant out of two must still flag the export as failed"""
    platform = build_platform(export_mssp=True)
    monkeypatch.setattr(platform, "_get", lambda *a, **kw: ({"value": []}, 200))
    monkeypatch.setattr(time, "sleep", lambda *a: None)

    def _post(*args, tenant_id=None, **kwargs):
        if tenant_id == "tenant-panucci":
            return BAD_REQUEST
        return {"id": "rule-anchovy"}, 201

    monkeypatch.setattr(platform, "_post", _post)

    error = export_rule(
        parameters={},
        rule_content=RULE_CONTENT,
        rule_converted=RULE_CONVERTED,
        platform=platform,
        rule_file=RULE_FILE,
        error=False,
        logger_param=LOGGER_PARAM,
    )

    assert error is True


@pytest.mark.parametrize("export_mssp", [False, True])
def test_export_rule_flags_error_on_bad_request(xdr_bad_request, export_mssp):
    """export_rule() must report error=True so the CLI exits non-zero"""
    platform = xdr_bad_request(export_mssp)

    error = export_rule(
        parameters={},
        rule_content=RULE_CONTENT,
        rule_converted=RULE_CONVERTED,
        platform=platform,
        rule_file=RULE_FILE,
        error=False,
        logger_param=LOGGER_PARAM,
    )

    assert error is True
