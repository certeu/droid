"""
Tests of the search hit logging

A hit must be reported with one WARNING per tenant/customer, and the wording
must be the same across the platforms.
"""

import re

import pytest

from droid import search as search_module
from droid.platforms import sentinel as sentinel_module
from droid.platforms.sentinel import SentinelPlatform
from droid.search import (
    search_rule_ms_xdr,
    search_rule_ms_xdr_mssp,
    search_rule_sentinel,
    search_rule_sentinel_mssp,
)

LOGGER_PARAM = {
    "debug_mode": False,
    "json_enabled": False,
    "json_stdout": False,
    "log_file": None,
}

RULE_FILE = "rules/sigma/delivery/anchovy_smuggling_on_neptune.yml"
RULE_CONTENT = {"id": "0c1b1b1a-0000-0000-0000-0000deadbeef", "title": "Anchovy smuggling"}

# One WARNING per customer, same shape on every platform
PER_CUSTOMER_HIT = re.compile(
    r"^\((?:XDR|Sentinel) MSSP\) (\d+) hit\(s\) found for (.+) on customer '(.+)'$"
)


class RecordingLogger:
    """Stand-in for ColorLogger capturing the emitted messages"""

    def __init__(self, *args, **kwargs):
        self.records = []

    def debug(self, message, *args, **kwargs):
        self.records.append(("DEBUG", message))

    def info(self, message, *args, **kwargs):
        self.records.append(("INFO", message))

    def warning(self, message, *args, **kwargs):
        self.records.append(("WARNING", message))

    def error(self, message, *args, **kwargs):
        self.records.append(("ERROR", message))

    def messages(self, level):
        return [message for lvl, message in self.records if lvl == level]


@pytest.fixture
def logger(monkeypatch):
    """Capture what droid.search logs instead of printing it"""
    recorder = RecordingLogger()
    monkeypatch.setattr(search_module, "ColorLogger", lambda *a, **kw: recorder)
    return recorder


class FakeXDRPlatform:
    """Minimal Microsoft XDR platform returning canned hit counts per tenant"""

    def __init__(self, export_list, hits_per_tenant):
        self._export_list = export_list
        self._hits_per_tenant = hits_per_tenant
        self._convert_rule_callback = None

    def get_export_list_mssp(self):
        return self._export_list

    def run_xdr_search(self, rule_converted, rule_file, tenant_id=None):
        return self._hits_per_tenant[tenant_id]


class FakeSentinelPlatform:
    """Minimal Sentinel platform returning a canned total hit count"""

    def __init__(self, total_hits):
        self._total_hits = total_hits

    def run_sentinel_search(self, rule_converted, rule_file, mssp_mode):
        return self._total_hits

    def run_sentinel_search_mssp_designated(self, rule_converted, rule_file, rule_content):
        return self._total_hits


PLANET_EXPRESS = {"tenant_id": "tenant-planet-express", "customer_name": "Planet Express"}
PANUCCI = {"tenant_id": "tenant-panucci", "customer_name": "Panucci's Pizza"}


def call_xdr_mssp(logger, export_list, hits_per_tenant):
    platform = FakeXDRPlatform(export_list, hits_per_tenant)
    return search_rule_ms_xdr_mssp(
        "DeviceNetworkEvents | where RemotePort == 22",
        RULE_CONTENT,
        platform,
        RULE_FILE,
        parameters={},
        logger=logger,
        error=False,
        search_warning=False,
    )


def test_xdr_mssp_logs_one_warning_per_tenant(logger):
    """Each tenant with a hit gets its own WARNING naming the customer"""
    error, search_warning = call_xdr_mssp(
        logger,
        {"group1": PLANET_EXPRESS, "group2": PANUCCI},
        {"tenant-planet-express": 3, "tenant-panucci": 1},
    )

    warnings = logger.messages("WARNING")

    assert f"(XDR MSSP) 3 hit(s) found for {RULE_FILE} on customer 'Planet Express'" in warnings
    assert f"(XDR MSSP) 1 hit(s) found for {RULE_FILE} on customer 'Panucci's Pizza'" in warnings
    assert error is False
    assert search_warning is True


def test_xdr_mssp_logs_the_total(logger):
    """The per-tenant hits are summed up in a final WARNING"""
    call_xdr_mssp(
        logger,
        {"group1": PLANET_EXPRESS, "group2": PANUCCI},
        {"tenant-planet-express": 3, "tenant-panucci": 1},
    )

    assert f"(XDR MSSP) 4 hit(s) found in total for {RULE_FILE}" in logger.messages("WARNING")


def test_xdr_mssp_only_warns_for_tenants_with_hits(logger):
    """A tenant without hit stays at INFO level"""
    error, search_warning = call_xdr_mssp(
        logger,
        {"group1": PLANET_EXPRESS, "group2": PANUCCI},
        {"tenant-planet-express": 2, "tenant-panucci": 0},
    )

    warnings = logger.messages("WARNING")

    assert f"(XDR MSSP) 2 hit(s) found for {RULE_FILE} on customer 'Planet Express'" in warnings
    assert not [w for w in warnings if "Panucci's Pizza" in w]
    assert f"(XDR MSSP) No hits for {RULE_FILE} on customer 'Panucci's Pizza'" in logger.messages("INFO")
    assert search_warning is True


def test_xdr_mssp_without_hit_does_not_warn(logger):
    """No hit at all means no WARNING and no total"""
    error, search_warning = call_xdr_mssp(
        logger,
        {"group1": PLANET_EXPRESS, "group2": PANUCCI},
        {"tenant-planet-express": 0, "tenant-panucci": 0},
    )

    assert logger.messages("WARNING") == []
    assert error is False
    assert search_warning is False


def test_xdr_mssp_falls_back_to_the_tenant_id(logger):
    """Without customer_name the tenant id is used to identify the customer"""
    call_xdr_mssp(
        logger,
        {"group1": {"tenant_id": "tenant-slurm-factory"}},
        {"tenant-slurm-factory": 1},
    )

    assert (
        f"(XDR MSSP) 1 hit(s) found for {RULE_FILE} on customer 'tenant-slurm-factory'"
        in logger.messages("WARNING")
    )


def test_xdr_mssp_keeps_searching_after_a_tenant_error(logger):
    """A failing tenant is reported but the remaining tenants are still searched"""

    class FailingPlatform(FakeXDRPlatform):
        def run_xdr_search(self, rule_converted, rule_file, tenant_id=None):
            if tenant_id == "tenant-planet-express":
                raise Exception("Delivery boy is missing")
            return self._hits_per_tenant[tenant_id]

    platform = FailingPlatform(
        {"group1": PLANET_EXPRESS, "group2": PANUCCI},
        {"tenant-panucci": 2},
    )

    error, search_warning = search_rule_ms_xdr_mssp(
        "DeviceNetworkEvents | where RemotePort == 22",
        RULE_CONTENT,
        platform,
        RULE_FILE,
        parameters={},
        logger=logger,
        error=False,
        search_warning=False,
    )

    assert error is True
    assert search_warning is True
    assert (
        f"(XDR MSSP) 2 hit(s) found for {RULE_FILE} on customer 'Panucci's Pizza'"
        in logger.messages("WARNING")
    )


@pytest.mark.parametrize(
    "hits,expected_warning",
    [
        (5, f"(XDR) 5 hit(s) found for {RULE_FILE}"),
        (1, f"(XDR) 1 hit(s) found for {RULE_FILE}"),
    ],
)
def test_xdr_single_tenant_warning(logger, hits, expected_warning):
    """Single tenant mode warns with the platform prefix"""

    class SingleTenantPlatform:
        def run_xdr_search(self, rule_converted, rule_file, tenant_id=None):
            return hits

    error, search_warning = search_rule_ms_xdr(
        "DeviceNetworkEvents",
        SingleTenantPlatform(),
        RULE_FILE,
        parameters={},
        logger=logger,
        error=False,
        search_warning=False,
    )

    assert expected_warning in logger.messages("WARNING")
    assert search_warning is True


def test_sentinel_single_workspace_warning(logger):
    """Sentinel uses the same wording as Microsoft XDR"""
    error, search_warning = search_rule_sentinel(
        "SecurityEvent",
        FakeSentinelPlatform(total_hits=5),
        RULE_FILE,
        parameters={},
        logger=logger,
        error=False,
        search_warning=False,
        mssp_mode=False,
    )

    assert f"(Sentinel) 5 hit(s) found for {RULE_FILE}" in logger.messages("WARNING")
    assert search_warning is True


def test_sentinel_mssp_logs_the_total(logger):
    """Sentinel MSSP sums up the hits like Microsoft XDR does"""
    error, search_warning = search_rule_sentinel_mssp(
        "SecurityEvent",
        RULE_CONTENT,
        FakeSentinelPlatform(total_hits=4),
        RULE_FILE,
        parameters={},
        logger=logger,
        error=False,
        search_warning=False,
    )

    assert f"(Sentinel MSSP) 4 hit(s) found in total for {RULE_FILE}" in logger.messages("WARNING")
    assert search_warning is True


def build_sentinel_platform(export_list_mssp):
    parameters = {
        "threshold_operator": "GreaterThan",
        "threshold_value": 0,
        "suppress_status": False,
        "incident_status": True,
        "grouping_reopen": False,
        "grouping_status": False,
        "grouping_period": 24,
        "grouping_method": "AllEntityMatch",
        "suppress_period": 5,
        "query_frequency": 1,
        "query_period": 1,
        "subscription_id": "sub-new-new-york",
        "resource_group": "rg-planet-express",
        "workspace_id": "ws-planet-express",
        "workspace_name": "planet-express",
        "days_ago": 1,
        "timeout": 60,
        "search_auth": "default",
        "export_auth": "default",
        "export_list_mssp": export_list_mssp,
    }
    return SentinelPlatform(parameters, LOGGER_PARAM)


class FakeTable:
    def __init__(self, rows):
        self.rows = rows


class FakeResults:
    def __init__(self, rows):
        self.status = sentinel_module.LogsQueryStatus.SUCCESS
        self.tables = [FakeTable(rows)]


def test_sentinel_mssp_designated_logs_one_warning_per_customer(monkeypatch):
    """Sentinel warns per customer with the same wording as Microsoft XDR"""
    hits_per_workspace = {"ws-planet-express": 3, "ws-panucci": 0}

    class FakeLogsQueryClient:
        def __init__(self, credential):
            pass

        def query_workspace(self, workspace_id, query, timespan=None, server_timeout=None):
            return FakeResults([("row",)] * hits_per_workspace[workspace_id])

    platform = build_sentinel_platform(
        {
            "group1": {
                "workspace_id": "ws-planet-express",
                "workspace_name": "planet-express",
                "customer_name": "Planet Express",
            },
            "group2": {
                "workspace_id": "ws-panucci",
                "workspace_name": "panucci",
                "customer_name": "Panucci's Pizza",
            },
        }
    )
    recorder = RecordingLogger()
    platform.logger = recorder
    monkeypatch.setattr(platform, "get_credentials", lambda scope=None: None)
    monkeypatch.setattr(sentinel_module, "LogsQueryClient", FakeLogsQueryClient)

    total = platform.run_sentinel_search_mssp_designated("SecurityEvent", RULE_FILE, RULE_CONTENT)

    assert total == 3
    assert (
        f"(Sentinel MSSP) 3 hit(s) found for {RULE_FILE} on customer 'Planet Express'"
        in recorder.messages("WARNING")
    )
    assert (
        f"(Sentinel MSSP) No hits for {RULE_FILE} on customer 'Panucci's Pizza'"
        in recorder.messages("INFO")
    )
    assert not [w for w in recorder.messages("WARNING") if "Panucci's Pizza" in w]


def test_sentinel_mssp_designated_falls_back_to_the_workspace_name(monkeypatch):
    """Without customer_name the workspace name identifies the customer"""

    class FakeLogsQueryClient:
        def __init__(self, credential):
            pass

        def query_workspace(self, workspace_id, query, timespan=None, server_timeout=None):
            return FakeResults([("row",)])

    platform = build_sentinel_platform(
        {"group1": {"workspace_id": "ws-slurm", "workspace_name": "slurm-factory"}}
    )
    recorder = RecordingLogger()
    platform.logger = recorder
    monkeypatch.setattr(platform, "get_credentials", lambda scope=None: None)
    monkeypatch.setattr(sentinel_module, "LogsQueryClient", FakeLogsQueryClient)

    platform.run_sentinel_search_mssp_designated("SecurityEvent", RULE_FILE, RULE_CONTENT)

    assert (
        f"(Sentinel MSSP) 1 hit(s) found for {RULE_FILE} on customer 'slurm-factory'"
        in recorder.messages("WARNING")
    )


def test_per_customer_wording_is_harmonised(logger, monkeypatch):
    """Microsoft XDR and Sentinel emit per-customer hits in the same format"""

    class FakeLogsQueryClient:
        def __init__(self, credential):
            pass

        def query_workspace(self, workspace_id, query, timespan=None, server_timeout=None):
            return FakeResults([("row",), ("row",)])

    call_xdr_mssp(logger, {"group1": PLANET_EXPRESS}, {"tenant-planet-express": 2})
    xdr_warning = [w for w in logger.messages("WARNING") if "on customer" in w]

    platform = build_sentinel_platform(
        {
            "group1": {
                "workspace_id": "ws-planet-express",
                "workspace_name": "planet-express",
                "customer_name": "Planet Express",
            }
        }
    )
    recorder = RecordingLogger()
    platform.logger = recorder
    monkeypatch.setattr(platform, "get_credentials", lambda scope=None: None)
    monkeypatch.setattr(sentinel_module, "LogsQueryClient", FakeLogsQueryClient)
    platform.run_sentinel_search_mssp_designated("SecurityEvent", RULE_FILE, RULE_CONTENT)
    sentinel_warning = [w for w in recorder.messages("WARNING") if "on customer" in w]

    assert len(xdr_warning) == 1
    assert len(sentinel_warning) == 1

    xdr_match = PER_CUSTOMER_HIT.match(xdr_warning[0])
    sentinel_match = PER_CUSTOMER_HIT.match(sentinel_warning[0])

    assert xdr_match, xdr_warning[0]
    assert sentinel_match, sentinel_warning[0]
    # Same hit count, same rule and same customer reported the same way
    assert xdr_match.groups() == sentinel_match.groups()
