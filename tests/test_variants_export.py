"""
Tests of the variant-aware export to MSSP customers
"""

import pytest

from droid.platforms.ms_xdr import MicrosoftXDRPlatform
from droid.variants import Variant, variant_rule_content


LOGGER_PARAM = {"debug_mode": False, "json_enabled": False}

SIGMA_RULE = {
    "id": "8a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
    "title": "Suspicious process",
    "description": "A suspicious process was started",
    "level": "high",
    "status": "stable",
    "logsource": {"category": "process_creation", "product": "windows"},
}

XDR_PARAMETERS = {
    "query_period": "0",
    "search_auth": "default",
    "export_auth": "default",
    "export_list_mssp": {
        "Zoidberg": {
            "tenant_id": "tenant-zoidberg",
            "customer_name": "Zoidberg",
            "variants": ["defender", "thirdparty"],
        },
        "Slurm": {
            "tenant_id": "tenant-slurm",
            "customer_name": "Slurm",
            "variants": ["thirdparty"],
        },
        "Nibbler": {
            "tenant_id": "tenant-nibbler",
            "customer_name": "Nibbler",
        },
    },
}


def _xdr_platform_recording_pushes():
    """An XDR platform in MSSP mode whose pushes are captured instead of sent"""

    platform = MicrosoftXDRPlatform(XDR_PARAMETERS, LOGGER_PARAM, export_mssp=True)
    pushed = []
    platform.push_detection_rule = lambda **kwargs: pushed.append(kwargs["tenant_id"])

    return platform, pushed


def test_export_skips_customers_that_do_not_carry_the_variant():
    """Slurm only has third-party EDR data, so the native Defender query — which
    would silently return nothing in their tenant — must never be pushed there."""

    platform, pushed = _xdr_platform_recording_pushes()
    defender = variant_rule_content(SIGMA_RULE, Variant("defender", "group_defender", {}, True))

    platform.create_rule(defender, "DeviceProcessEvents", "rule.yml")

    assert pushed == ["tenant-zoidberg", "tenant-nibbler"]


def test_export_reaches_every_customer_carrying_the_variant():
    """Both customers declaring the third-party source receive that variant, and
    so does the customer declaring no allowlist at all."""

    platform, pushed = _xdr_platform_recording_pushes()
    thirdparty = variant_rule_content(SIGMA_RULE, Variant("thirdparty", "group_thirdparty", {}, False))

    platform.create_rule(thirdparty, "DeviceProcessEvents", "rule.yml")

    assert pushed == ["tenant-zoidberg", "tenant-slurm", "tenant-nibbler"]


def test_export_without_variants_reaches_every_customer():
    """A rule converted outside the fan-out is deployed exactly as before."""

    platform, pushed = _xdr_platform_recording_pushes()

    platform.create_rule(dict(SIGMA_RULE), "DeviceProcessEvents", "rule.yml")

    assert pushed == ["tenant-zoidberg", "tenant-slurm", "tenant-nibbler"]


def test_skipped_customer_still_holding_the_rule_is_reported():
    """A customer who stops carrying a telemetry source keeps whatever was already
    deployed there. Dropping them from the allowlist silently leaves a rule running
    against data they no longer have, so the leftover must be reported — but never
    deleted, since only the operator knows whether it is still wanted.
    """

    platform, _ = _xdr_platform_recording_pushes()
    warnings = []
    platform.logger.warning = lambda message, *args, **kwargs: warnings.append(message)
    platform.get_rule = lambda rule_id, tenant_id=None: {"id": "deployed"}

    defender = variant_rule_content(SIGMA_RULE, Variant("defender", "group_defender", {}, True))
    platform.create_rule(defender, "DeviceProcessEvents", "rule.yml")

    assert len(warnings) == 1
    assert "tenant-slurm" in warnings[0]
    assert "defender" in warnings[0]


def test_skipped_customer_without_the_rule_is_not_reported():
    """Nothing deployed, nothing to report."""

    platform, _ = _xdr_platform_recording_pushes()
    warnings = []
    platform.logger.warning = lambda message, *args, **kwargs: warnings.append(message)
    platform.get_rule = lambda rule_id, tenant_id=None: None

    defender = variant_rule_content(SIGMA_RULE, Variant("defender", "group_defender", {}, True))
    platform.create_rule(defender, "DeviceProcessEvents", "rule.yml")

    assert warnings == []


SENTINEL_PARAMETERS = {
    "threshold_operator": "GreaterThan",
    "threshold_value": 0,
    "suppress_status": False,
    "incident_status": True,
    "grouping_reopen": False,
    "grouping_status": False,
    "grouping_period": 24,
    "grouping_method": "AllEntities",
    "suppress_period": 1,
    "query_frequency": 1,
    "query_period": 1,
    "subscription_id": "sub-default",
    "resource_group": "rg-default",
    "workspace_id": "ws-default",
    "workspace_name": "workspace-default",
    "days_ago": 1,
    "timeout": 120,
    "search_auth": "default",
    "export_auth": "default",
    "export_list_mssp": {
        "Zoidberg": {
            "tenant_id": "tenant-zoidberg",
            "customer_name": "Zoidberg",
            "subscription_id": "sub-zoidberg",
            "resource_group_name": "rg-zoidberg",
            "workspace_name": "workspace-zoidberg",
            "variants": ["defender", "thirdparty"],
        },
        "Slurm": {
            "tenant_id": "tenant-slurm",
            "customer_name": "Slurm",
            "subscription_id": "sub-slurm",
            "resource_group_name": "rg-slurm",
            "workspace_name": "workspace-slurm",
            "variants": ["thirdparty"],
        },
    },
}


class FakeAlertRules:
    """Captures create_or_update instead of reaching Azure"""

    def __init__(self, subscription_id, pushed):
        self._subscription_id = subscription_id
        self._pushed = pushed

    def create_or_update(self, resource_group_name, workspace_name, rule_id, alert_rule):
        self._pushed.append(workspace_name)


def _sentinel_platform(monkeypatch, deployed_rule):
    """A Sentinel platform in MSSP mode, with the Azure client stubbed out

    Return: the platform and the list of workspaces it pushed to
    """

    from droid.platforms import sentinel

    pushed = []

    class FakeSecurityInsights:
        def __init__(self, credential, subscription_id):
            self.alert_rules = FakeAlertRules(subscription_id, pushed)

    monkeypatch.setattr(sentinel, "SecurityInsights", FakeSecurityInsights)

    platform = sentinel.SentinelPlatform(SENTINEL_PARAMETERS, LOGGER_PARAM, export_mssp=True)
    platform.get_credentials = lambda: None
    platform.get_rule_mssp = lambda *args, **kwargs: deployed_rule

    return platform, pushed


def test_sentinel_skipped_workspace_still_holding_the_rule_is_reported(monkeypatch):
    """Same leftover as on XDR, keyed by workspace rather than tenant."""

    platform, pushed = _sentinel_platform(monkeypatch, deployed_rule={"name": "deployed"})
    warnings = []
    platform.logger.warning = lambda message, *args, **kwargs: warnings.append(message)

    defender = variant_rule_content(SIGMA_RULE, Variant("defender", "group_defender", {}, True))
    platform.create_rule(defender, "SecurityEvent", "rule.yml")

    assert pushed == ["workspace-zoidberg"]
    assert len(warnings) == 1
    assert "workspace-slurm" in warnings[0]
    assert "defender" in warnings[0]


def test_sentinel_pushes_a_variant_to_every_workspace_carrying_it(monkeypatch):
    """The third-party variant reaches both workspaces and reports no orphan."""

    platform, pushed = _sentinel_platform(monkeypatch, deployed_rule={"name": "deployed"})
    warnings = []
    platform.logger.warning = lambda message, *args, **kwargs: warnings.append(message)

    thirdparty = variant_rule_content(SIGMA_RULE, Variant("thirdparty", "group_thirdparty", {}, False))
    platform.create_rule(thirdparty, "SecurityEvent", "rule.yml")

    assert pushed == ["workspace-zoidberg", "workspace-slurm"]
    assert warnings == []


def test_a_log_source_without_variants_still_reaches_every_customer():
    """A customer allowlist names the telemetry they have *where there is a choice*.

    Most log sources are served by a single pipeline group with no `variant` key
    at all. Those rules must keep deploying to every customer — otherwise adding
    `variants` to one customer to pick their process_creation source would
    silently stop every other rule in the repository reaching them.
    """

    platform, pushed = _xdr_platform_recording_pushes()
    from droid.variants import resolve_variants, variant_rule_content

    pipelines_config = {"windows_process_creation": {"pipelines": [], "product": "windows",
                                                     "category": "process_creation"}}
    variants = resolve_variants(SIGMA_RULE, pipelines_config)
    content = variant_rule_content(SIGMA_RULE, variants[0])

    platform.create_rule(content, "DeviceProcessEvents", "rule.yml")

    assert pushed == ["tenant-zoidberg", "tenant-slurm", "tenant-nibbler"]
