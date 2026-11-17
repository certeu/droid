"""
Tests of the tenant droid authenticates against in Sentinel MSSP mode

With Azure Lighthouse the client workspaces are delegated to the managing
tenant, which must issue every token: mssp_auth_tenant_id names it, for every
MSSP operation. Without it, droid keeps authenticating against the tenant of
each workspace.
"""

import copy
from types import SimpleNamespace

import pytest

from droid.config import load_platform_config
from droid.platforms import sentinel


LOGGER_PARAM = {"debug_mode": False, "json_enabled": False}

RULE_FILE = "rule.yml"

SIGMA_RULE = {
    "id": "89098061-c553-4004-becc-d7a0a021bbb1",
    "title": "Scheduled task created from a temporary folder",
    "description": "A scheduled task runs a binary from a temporary folder",
    "level": "critical",
    "status": "stable",
    "tags": ["attack.persistence", "attack.t1053.005"],
    "logsource": {"product": "windows", "category": "process_creation"},
}

PARAMETERS = {
    "threshold_operator": "GreaterThan",
    "threshold_value": 0,
    "suppress_status": False,
    "incident_status": True,
    "grouping_reopen": False,
    "grouping_status": False,
    "grouping_period": 5,
    "grouping_method": "AllEntities",
    "query_frequency": 1,
    "query_period": 2,
    "subscription_id": "sub-planet-express",
    "resource_group": "rg-planet-express",
    "workspace_id": "ws-planet-express",
    "workspace_name": "planet-express",
    "days_ago": 1,
    "timeout": 120,
    "search_auth": "app",
    "export_auth": "app",
    "tenant_id": "tenant-planet-express",
    "client_id": "client-hermes",
    "client_secret": "not-a-secret",
}

CUSTOMERS = {
    "group1": {
        "tenant_id": "tenant-panucci",
        "subscription_id": "sub-panucci",
        "resource_group_name": "rg-panucci",
        "workspace_name": "panucci",
        "workspace_id": "ws-panucci",
        "customer_name": "Panucci's Pizza",
    },
    "group2": {
        "tenant_id": "tenant-mom-corp",
        "subscription_id": "sub-mom-corp",
        "resource_group_name": "rg-mom-corp",
        "workspace_name": "mom-corp",
        "workspace_id": "ws-mom-corp",
        "customer_name": "Mom Corp",
    },
}

MANAGING_TENANT = "tenant-planet-express-lighthouse"


def tenant_of(credential):
    # A credential of the token hook carries no tenant
    return getattr(credential, "tenant_id", None)


class RecordingCredential:
    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id


class FakeTable:
    rows = []


class FakeResults:
    status = sentinel.LogsQueryStatus.SUCCESS
    tables = [FakeTable()]


@pytest.fixture(autouse=True)
def no_token_hook(monkeypatch):
    """Make sure the tests are not influenced by the environment"""
    monkeypatch.delenv("DROID_AZURE_TOKEN_HOOK", raising=False)


@pytest.fixture
def azure(monkeypatch):
    """Stand in for Azure, recording the tenant of the credential of every call"""
    tenants = []

    class FakeAlertRules:
        def __init__(self, credential):
            self.credential = credential

        def get(self, resource_group_name, workspace_name, rule_id):
            tenants.append(("get", workspace_name, tenant_of(self.credential)))
            raise sentinel.ResourceNotFoundError("Not found")

        def delete(self, resource_group_name, workspace_name, rule_id):
            tenants.append(("delete", workspace_name, tenant_of(self.credential)))

        def create_or_update(self, resource_group_name, workspace_name, rule_id, alert_rule):
            tenants.append(("create", workspace_name, tenant_of(self.credential)))
            return alert_rule

    class FakeSecurityInsights:
        def __init__(self, credential, subscription_id):
            self.alert_rules = FakeAlertRules(credential)

    class FakeLogsQueryClient:
        def __init__(self, credential):
            self.credential = credential

        def query_workspace(self, workspace_id, query, timespan=None, server_timeout=None):
            tenants.append(("search", workspace_id, tenant_of(self.credential)))
            return FakeResults()

        def query_resource(self, resource_id, query, timespan=None, server_timeout=None):
            return self.query_workspace(resource_id, query, timespan, server_timeout)

    monkeypatch.setattr(sentinel, "ClientSecretCredential", RecordingCredential)
    monkeypatch.setattr(sentinel, "SecurityInsights", FakeSecurityInsights)
    monkeypatch.setattr(sentinel, "LogsQueryClient", FakeLogsQueryClient)

    return tenants


def build_platform(export_mssp=True, **overrides):
    return sentinel.SentinelPlatform(
        {**PARAMETERS, "export_list_mssp": CUSTOMERS, **overrides}, LOGGER_PARAM, export_mssp=export_mssp
    )


def tenants_of(calls, operation):
    return {workspace: tenant for op, workspace, tenant in calls if op == operation}


# Without mssp_auth_tenant_id: unchanged

def test_export_authenticates_against_each_workspace_tenant(azure):
    platform = build_platform()
    platform.create_rule(copy.deepcopy(SIGMA_RULE), "SecurityEvent", RULE_FILE)

    assert tenants_of(azure, "create") == {"panucci": "tenant-panucci", "mom-corp": "tenant-mom-corp"}


def test_deletion_authenticates_against_each_workspace_tenant(azure):
    platform = build_platform()
    platform.remove_rule(SIGMA_RULE, "SecurityEvent", RULE_FILE)

    assert tenants_of(azure, "delete") == {"panucci": "tenant-panucci", "mom-corp": "tenant-mom-corp"}


def test_rule_retrieval_authenticates_against_the_workspace_tenant(azure):
    platform = build_platform()
    platform.get_rule_mssp(SIGMA_RULE, RULE_FILE, "tenant-panucci", "sub-panucci", "rg-panucci", "panucci")

    assert tenants_of(azure, "get") == {"panucci": "tenant-panucci"}


def test_designated_search_authenticates_against_the_platform_tenant(azure):
    platform = build_platform(export_mssp=False)
    platform.run_sentinel_search_mssp_designated("SecurityEvent", RULE_FILE, SIGMA_RULE)

    assert tenants_of(azure, "search") == {
        "ws-panucci": "tenant-planet-express",
        "ws-mom-corp": "tenant-planet-express",
    }


def test_mssp_operations_leave_the_platform_tenant_alone(azure):
    """A loop over the customers used to switch the tenant of the platform
    to the last customer's, for whatever ran after it"""
    platform = build_platform()
    platform.create_rule(copy.deepcopy(SIGMA_RULE), "SecurityEvent", RULE_FILE)
    platform.remove_rule(SIGMA_RULE, "SecurityEvent", RULE_FILE)
    platform.get_rule_mssp(SIGMA_RULE, RULE_FILE, "tenant-panucci", "sub-panucci", "rg-panucci", "panucci")

    assert platform._tenant_id == "tenant-planet-express"


# With mssp_auth_tenant_id: the managing tenant, everywhere

def test_export_authenticates_against_the_managing_tenant(azure):
    platform = build_platform(mssp_auth_tenant_id=MANAGING_TENANT)
    platform.create_rule(copy.deepcopy(SIGMA_RULE), "SecurityEvent", RULE_FILE)

    assert tenants_of(azure, "create") == {"panucci": MANAGING_TENANT, "mom-corp": MANAGING_TENANT}
    # Export reads the deployed rule first
    assert set(tenants_of(azure, "get").values()) == {MANAGING_TENANT}


def test_deletion_authenticates_against_the_managing_tenant(azure):
    platform = build_platform(mssp_auth_tenant_id=MANAGING_TENANT)
    platform.remove_rule(SIGMA_RULE, "SecurityEvent", RULE_FILE)

    assert tenants_of(azure, "delete") == {"panucci": MANAGING_TENANT, "mom-corp": MANAGING_TENANT}


def test_rule_retrieval_authenticates_against_the_managing_tenant(azure):
    """Integrity reads the rule of each customer through get_rule_mssp"""
    platform = build_platform(mssp_auth_tenant_id=MANAGING_TENANT)
    platform.get_rule_mssp(SIGMA_RULE, RULE_FILE, "tenant-panucci", "sub-panucci", "rg-panucci", "panucci")

    assert tenants_of(azure, "get") == {"panucci": MANAGING_TENANT}


def test_orphan_check_authenticates_against_the_managing_tenant(azure):
    platform = build_platform(mssp_auth_tenant_id=MANAGING_TENANT)
    platform.report_orphan_variant(SIGMA_RULE, RULE_FILE, "sysmon", "Mom Corp", CUSTOMERS["group2"])

    assert tenants_of(azure, "get") == {"mom-corp": MANAGING_TENANT}


def test_designated_search_authenticates_against_the_managing_tenant(azure):
    platform = build_platform(export_mssp=False, mssp_auth_tenant_id=MANAGING_TENANT)
    platform.run_sentinel_search_mssp_designated("SecurityEvent", RULE_FILE, SIGMA_RULE)

    assert tenants_of(azure, "search") == {"ws-panucci": MANAGING_TENANT, "ws-mom-corp": MANAGING_TENANT}


def test_all_workspaces_search_authenticates_against_the_managing_tenant(azure):
    platform = build_platform(export_mssp=False, mssp_auth_tenant_id=MANAGING_TENANT)
    platform._client_workspaces = [{"customer": "panucci", "workspace_id": "ws-panucci"}]
    platform.run_sentinel_search("SecurityEvent", RULE_FILE, mssp_mode=True, rule_content=SIGMA_RULE)

    assert tenants_of(azure, "search") == {"ws-panucci": MANAGING_TENANT}


def test_single_workspace_ignores_the_managing_tenant(azure):
    """mssp_auth_tenant_id is about the MSSP workspaces only"""
    platform = build_platform(export_mssp=False, mssp_auth_tenant_id=MANAGING_TENANT)
    platform.create_rule(copy.deepcopy(SIGMA_RULE), "SecurityEvent", RULE_FILE)

    assert tenants_of(azure, "create") == {"planet-express": "tenant-planet-express"}


# Token hook

@pytest.fixture
def token_hook(monkeypatch):
    """Point DROID_AZURE_TOKEN_HOOK at a fake hook recording the URLs called"""
    urls = []

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"access_token": "a-token"}

    def fake_get(url, **kwargs):
        urls.append(url)
        return FakeResponse()

    monkeypatch.setenv("DROID_AZURE_TOKEN_HOOK", "https://hook.planet-express.local/token?tenant={TENANT_ID}")
    monkeypatch.setattr(sentinel.requests, "get", fake_get)

    return urls


def test_token_hook_is_asked_for_the_managing_tenant(azure, token_hook):
    platform = build_platform(mssp_auth_tenant_id=MANAGING_TENANT)
    platform.remove_rule(SIGMA_RULE, "SecurityEvent", RULE_FILE)

    assert token_hook == [f"https://hook.planet-express.local/token?tenant={MANAGING_TENANT}"]


def test_token_hook_is_asked_for_the_workspace_tenant_by_default(azure, token_hook):
    platform = build_platform()
    platform.get_rule_mssp(SIGMA_RULE, RULE_FILE, "tenant-mom-corp", "sub-mom-corp", "rg-mom-corp", "mom-corp")

    assert token_hook == ["https://hook.planet-express.local/token?tenant=tenant-mom-corp"]


# Configuration

def _load_config(tmp_path, monkeypatch, toml_extra="", env=None):
    monkeypatch.delenv("DROID_AZURE_MSSP_AUTH_TENANT_ID", raising=False)
    for name, value in (env or {}).items():
        monkeypatch.setenv(name, value)
    config_file = tmp_path / "droid.toml"
    config_file.write_text(
        "[platforms.microsoft_sentinel]\n"
        'search_auth = "default"\n'
        'export_auth = "default"\n'
        + toml_extra
    )
    parameters = SimpleNamespace(platform="microsoft_sentinel", search=True, export=False, integrity=False, convert=False)
    return load_platform_config(parameters, str(config_file))


def test_managing_tenant_from_the_configuration_file(tmp_path, monkeypatch):
    config = _load_config(tmp_path, monkeypatch, f'mssp_auth_tenant_id = "{MANAGING_TENANT}"\n')

    assert config["mssp_auth_tenant_id"] == MANAGING_TENANT


def test_managing_tenant_from_the_environment(tmp_path, monkeypatch):
    config = _load_config(tmp_path, monkeypatch, env={"DROID_AZURE_MSSP_AUTH_TENANT_ID": MANAGING_TENANT})

    assert config["mssp_auth_tenant_id"] == MANAGING_TENANT


def test_managing_tenant_is_optional(tmp_path, monkeypatch):
    config = _load_config(tmp_path, monkeypatch)

    assert "mssp_auth_tenant_id" not in config
