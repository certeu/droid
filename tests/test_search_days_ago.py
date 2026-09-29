"""
Tests of the per-rule search lookback

The platform parameters set one lookback for every rule. A rule overrides it
with the `days_ago` custom field, and every platform has to honour it in its
own time representation.
"""

import pytest

from droid.platforms import elastic as elastic_module
from droid.platforms import sentinel as sentinel_module
from droid.platforms import splunk as splunk_module
from droid.platforms.elastic import ElasticPlatform
from droid.platforms.ms_xdr import MicrosoftXDRPlatform
from droid.platforms.sentinel import SentinelPlatform
from droid.platforms.splunk import SplunkPlatform

LOGGER_PARAM = {"debug_mode": False, "json_enabled": False}

RULE_FILE = "rules/sigma/delivery/anchovy_smuggling_on_neptune.yml"

LOOKBACK_RULE = {
    "id": "0c1b1b1a-0000-0000-0000-0000deadbeef",
    "title": "Anchovy smuggling",
    "custom": {"days_ago": 7},
}

PLAIN_RULE = {
    "id": "0c1b1b1a-0000-0000-0000-0000deadbeef",
    "title": "Anchovy smuggling",
}


# ---------------------------------------------------------------------------
# Microsoft XDR
# ---------------------------------------------------------------------------

TENANT = "tenant-planet-express"

XDR_PARAMETERS = {
    "query_period": "1h",
    "days_ago": 1,
    "tenant_id": "tenant-planet-express",
    "search_auth": "default",
    "export_auth": "default",
}


def _xdr_platform_recording_payloads():
    """An XDR platform capturing the hunting payload instead of sending it"""

    platform = MicrosoftXDRPlatform(XDR_PARAMETERS, LOGGER_PARAM)
    payloads = []

    def fake_post(url, payload=None, tenant_id=None, timeout=None):
        payloads.append(payload)
        return {"results": []}, 200

    platform._post = fake_post

    return platform, payloads


def test_xdr_search_uses_the_platform_lookback_by_default():
    platform, payloads = _xdr_platform_recording_payloads()

    platform.run_xdr_search(
        "DeviceProcessEvents", RULE_FILE, tenant_id=TENANT, rule_content=PLAIN_RULE
    )

    assert payloads[0]["Timespan"] == "P1D"


def test_xdr_search_uses_the_rule_lookback():
    """The hunting timespan must follow the rule, not the platform default."""
    platform, payloads = _xdr_platform_recording_payloads()

    platform.run_xdr_search(
        "DeviceProcessEvents", RULE_FILE, tenant_id=TENANT, rule_content=LOOKBACK_RULE
    )

    assert payloads[0]["Timespan"] == "P7D"


def test_xdr_search_caps_the_rule_lookback_at_thirty_days():
    """Graph rejects a hunting query beyond 30 days, so the rule cannot ask for more."""
    platform, payloads = _xdr_platform_recording_payloads()

    platform.run_xdr_search(
        "DeviceProcessEvents", RULE_FILE, tenant_id=TENANT, rule_content={"custom": {"days_ago": 90}}
    )

    assert payloads[0]["Timespan"] == "P30D"


# ---------------------------------------------------------------------------
# Microsoft Sentinel
# ---------------------------------------------------------------------------

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
    "subscription_id": "sub-planet-express",
    "resource_group": "rg-planet-express",
    "workspace_id": "ws-planet-express",
    "workspace_name": "planet-express",
    "days_ago": 1,
    "timeout": 60,
    "search_auth": "default",
    "export_auth": "default",
    "export_list_mssp": {
        "PlanetExpress": {
            "workspace_id": "ws-planet-express",
            "workspace_name": "planet-express",
            "customer_name": "Planet Express",
        }
    },
}


class FakeTable:
    def __init__(self, rows):
        self.rows = rows


class FakeResults:
    def __init__(self):
        self.status = sentinel_module.LogsQueryStatus.SUCCESS
        self.tables = [FakeTable([])]


def _sentinel_platform_recording_timespans(monkeypatch):
    """A Sentinel platform capturing the queried timespan instead of querying"""

    timespans = []

    class FakeLogsQueryClient:
        def __init__(self, credential):
            pass

        def query_workspace(self, workspace_id, query, timespan=None, server_timeout=None):
            timespans.append(timespan)
            return FakeResults()

    monkeypatch.setattr(sentinel_module, "LogsQueryClient", FakeLogsQueryClient)

    platform = SentinelPlatform(SENTINEL_PARAMETERS, LOGGER_PARAM)
    platform.get_credentials = lambda scope=None: None

    return platform, timespans


def _days_covered(timespan):
    start_time, current_time = timespan
    return round((current_time - start_time).total_seconds() / 86400)


def test_sentinel_search_uses_the_platform_lookback_by_default(monkeypatch):
    platform, timespans = _sentinel_platform_recording_timespans(monkeypatch)

    platform.run_sentinel_search("SecurityEvent", RULE_FILE, False, rule_content=PLAIN_RULE)

    assert _days_covered(timespans[0]) == 1


def test_sentinel_search_uses_the_rule_lookback(monkeypatch):
    platform, timespans = _sentinel_platform_recording_timespans(monkeypatch)

    platform.run_sentinel_search("SecurityEvent", RULE_FILE, False, rule_content=LOOKBACK_RULE)

    assert _days_covered(timespans[0]) == 7


def test_sentinel_mssp_search_uses_the_rule_lookback(monkeypatch):
    """The designated customer search already carries the rule content."""
    platform, timespans = _sentinel_platform_recording_timespans(monkeypatch)

    platform.run_sentinel_search_mssp_designated("SecurityEvent", RULE_FILE, LOOKBACK_RULE)

    assert _days_covered(timespans[0]) == 7


# ---------------------------------------------------------------------------
# Splunk
# ---------------------------------------------------------------------------

SPLUNK_PARAMETERS = {
    "url": "splunksh.planet-express.local",
    "port": "8089",
    "user": "bender",
    "password": "bite-my-shiny",
    "app": "pizza_app_rules",
    "test_earliest_time": "-24h@h",
    "test_latest_time": "now",
    "earliest_time": "-1h@h",
    "latest_time": "now",
    "cron_schedule": "0 * * * *",
    "job_ttl": 86400,
    "acl_update_owner": "nobody",
    "acl_update_perms_read": "group1",
    "savedsearch_parameters": {},
}


class FakeJob:
    """A Splunk job that is done as soon as it is looked at"""

    def __init__(self):
        self._fields = {
            "isDone": "1",
            "isFailed": "0",
            "doneProgress": "1.0",
            "scanCount": "0",
            "eventCount": "0",
            "resultCount": "0",
            "sid": "sid-1",
        }

    def __getitem__(self, key):
        return self._fields[key]

    def is_ready(self):
        return True

    def set_ttl(self, ttl):
        pass

    def acl_update(self, **kwargs):
        pass


def _splunk_platform_recording_jobs(monkeypatch):
    """A Splunk platform capturing the job parameters instead of connecting"""

    jobs = []

    class FakeJobs:
        def create(self, query, **kwargs):
            jobs.append(kwargs)
            return FakeJob()

    class FakeService:
        jobs = FakeJobs()

    monkeypatch.setattr(
        splunk_module.client, "connect", lambda **kwargs: FakeService()
    )

    return SplunkPlatform(SPLUNK_PARAMETERS, LOGGER_PARAM), jobs


def test_splunk_search_uses_the_platform_lookback_by_default(monkeypatch):
    platform, jobs = _splunk_platform_recording_jobs(monkeypatch)

    platform.run_splunk_search("index=main", RULE_FILE, rule_content=PLAIN_RULE)

    assert jobs[0]["earliest_time"] == "-24h@h"


def test_splunk_search_uses_the_rule_lookback(monkeypatch):
    """A rule lookback is expressed in days as a Splunk relative time modifier."""
    platform, jobs = _splunk_platform_recording_jobs(monkeypatch)

    platform.run_splunk_search("index=main", RULE_FILE, rule_content=LOOKBACK_RULE)

    assert jobs[0]["earliest_time"] == "-7d"
    assert jobs[0]["latest_time"] == "now"


# ---------------------------------------------------------------------------
# Elastic Security
# ---------------------------------------------------------------------------

ELASTIC_PARAMETERS = {
    "kibana_url": "https://kibana.planet-express.local",
    "elastic_hosts": ["https://elastic.planet-express.local"],
    "eql_search_range_gte": "now-24h",
    "esql_search_range_gte": "now-1h",
    "auth_method": "basic",
    "username": "bender",
    "password": "bite-my-shiny",
}


def _elastic_platform_recording_filters(monkeypatch, language):
    """An Elastic platform capturing the range filter instead of searching"""

    filters = []

    class FakeEql:
        def search(self, index=None, query=None, filter=None, **kwargs):
            filters.append(filter)
            return {"id": "search-1"}

        def get_status(self, id=None):
            return {"is_running": False}

        def get(self, id=None):
            return {"hits": {"total": {"value": 0}}}

        def delete(self, id=None):
            pass

    class FakeEsql:
        def query(self, query=None, filter=None, **kwargs):
            filters.append(filter)
            return {"values": []}

    class FakeElasticsearch:
        def __init__(self, *args, **kwargs):
            self.eql = FakeEql()
            self.esql = FakeEsql()

    monkeypatch.setattr(elastic_module, "Elasticsearch", FakeElasticsearch)

    platform = ElasticPlatform(dict(ELASTIC_PARAMETERS), LOGGER_PARAM, language)
    platform._index_name = ["logs-*"]  # normally resolved while converting the rule

    return platform, filters


def _gte(range_filter):
    return range_filter["range"]["@timestamp"]["gte"]


def test_elastic_esql_search_uses_the_platform_lookback_by_default(monkeypatch):
    platform, filters = _elastic_platform_recording_filters(monkeypatch, "esql")

    platform.run_elastic_search("FROM logs", "esql", PLAIN_RULE)

    assert _gte(filters[0]) == "now-1h"


def test_elastic_esql_search_uses_the_rule_lookback(monkeypatch):
    platform, filters = _elastic_platform_recording_filters(monkeypatch, "esql")

    platform.run_elastic_search("FROM logs", "esql", LOOKBACK_RULE)

    assert _gte(filters[0]) == "now-7d"


def test_elastic_eql_search_uses_the_rule_lookback(monkeypatch):
    platform, filters = _elastic_platform_recording_filters(monkeypatch, "eql")

    platform.run_elastic_search("any where true", "eql", LOOKBACK_RULE)

    assert _gte(filters[0]) == "now-7d"


# ---------------------------------------------------------------------------
# The rule content has to reach the platform
# ---------------------------------------------------------------------------

class SearchParameters:
    """The CLI parameters the search dispatch reads"""

    def __init__(self, platform, mssp=False, sentinel_xdr=False):
        self.platform = platform
        self.mssp = mssp
        self.sentinel_xdr = sentinel_xdr


class RecordingPlatform:
    """A platform keeping the rule content every search method was given"""

    def __init__(self):
        self.seen = []
        self._convert_rule_callback = None

    def run_splunk_search(self, rule_converted, rule_file, rule_content=None):
        self.seen.append(rule_content)
        return {"resultCount": 0, "jobUrl": "https://splunk/job/1"}

    def run_sentinel_search(self, rule_converted, rule_file, mssp_mode, rule_content=None):
        self.seen.append(rule_content)
        return 0

    def run_sentinel_search_mssp_designated(self, rule_converted, rule_file, rule_content):
        self.seen.append(rule_content)
        return 0

    def run_xdr_search(self, rule_converted, rule_file, tenant_id=None, rule_content=None):
        self.seen.append(rule_content)
        return 0

    def run_elastic_search(self, rule_converted, language=None, rule_content=None):
        self.seen.append(rule_content)
        return 0

    def get_export_list_mssp(self):
        return {"group1": {"tenant_id": TENANT, "customer_name": "Planet Express"}}


@pytest.mark.parametrize(
    "parameters",
    [
        SearchParameters("splunk"),
        SearchParameters("esql"),
        SearchParameters("microsoft_sentinel"),
        SearchParameters("microsoft_sentinel", mssp=True),
        SearchParameters("microsoft_xdr"),
        SearchParameters("microsoft_xdr", mssp=True),
    ],
    ids=["splunk", "elastic", "sentinel", "sentinel_mssp", "xdr", "xdr_mssp"],
)
def test_the_search_dispatch_hands_the_rule_content_to_the_platform(parameters):
    """Without the rule content, no platform can honour a per-rule lookback."""
    from droid.search import search_rule

    platform = RecordingPlatform()

    search_rule(
        parameters,
        LOOKBACK_RULE,
        "a query",
        platform,
        RULE_FILE,
        error=False,
        search_warning=False,
        logger_param=LOGGER_PARAM,
    )

    assert platform.seen == [LOOKBACK_RULE]
