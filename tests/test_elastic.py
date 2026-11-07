"""
Tests of the Elastic Security platform: ES|QL conversion, rule export and search
"""

import os
import tomllib

import pytest

from droid.convert import Conversion, load_rule
from droid.platforms import elastic as elastic_module
from droid.platforms.elastic import ElasticPlatform, eql_backend, esql_backend
from sigma.backends.elasticsearch import EqlBackend, ESQLBackend

LOGGER_PARAM = {"debug_mode": False, "json_enabled": False}

CONFIG = "tests/files/test_config_elastic.toml"
SIGNIN_RULE = "tests/files/elastic/signin_attempts_rule.yml"
CORRELATION_RULE = "tests/files/sigma-rules/valid/convert_valid_correlation_rule.yml"

ELASTIC_PARAMETERS = {
    "kibana_url": "https://kibana.planet-express.local",
    "elastic_hosts": ["https://elastic.planet-express.local"],
    "auth_method": "basic",
    "username": "bender",
    "password": "bite-my-shiny",
    "schedule_interval": 5,
    "schedule_interval_unit": "m",
}


def convert(platform, rule):
    with open(CONFIG, "rb") as file:
        config = tomllib.load(file)
    conversion = Conversion(config["platforms"]["elastic"], config["base"], platform, LOGGER_PARAM)
    return conversion.convert_rule(load_rule(rule), rule, None)


def build_platform(language="esql", **overrides):
    return ElasticPlatform({**ELASTIC_PARAMETERS, **overrides}, LOGGER_PARAM, language)


# ---------------------------------------------------------------------------
# ES|QL conversion
# ---------------------------------------------------------------------------

def test_esql_query_starts_with_the_source_command():
    """The query reads like Elastic's own: FROM … METADATA …, then one command per line"""
    query = convert("esql", SIGNIN_RULE)

    assert query.startswith(
        "FROM *-signin-attempts-planet-express-* METADATA _id, _index, _version\n| WHERE "
    )


def test_esql_quotes_field_names_starting_with_a_digit():
    """ES|QL rejects `1vault.signinattempts.category` unless it is backtick quoted"""
    query = convert("esql", SIGNIN_RULE)

    assert '`1vault.signinattempts.target_user.email`=="fry@planet-express.local"' in query
    assert '`1vault.signinattempts.category`=="success"' in query
    assert "labels.module==" in query


def test_esql_quotes_field_names_with_a_reserved_segment():
    """`by` is reserved, even as the last segment of a dotted field name"""
    query = convert("esql", SIGNIN_RULE)

    assert '`delivery.by`=="Bender"' in query


def test_esql_operators_are_upper_case():
    query = convert("esql", SIGNIN_RULE)

    assert " AND NOT " in query
    assert " and " not in query


def test_esql_correlation_puts_each_command_on_its_own_line():
    query = convert("esql", CORRELATION_RULE)
    lines = query.strip().splitlines()

    assert lines[0] == "FROM logs-endpoint.events.process-* METADATA _id, _index, _version"
    assert [line.split()[1] for line in lines[1:]] == ["WHERE", "EVAL", "EVAL", "STATS", "WHERE"]
    assert " BY timebucket" in query


def test_eql_quotes_field_names_it_cannot_parse():
    """EQL reserves `by` too, and the backend only quotes a leading digit"""
    query = convert("eql", SIGNIN_RULE)

    assert query.startswith("any where ")
    assert '`1vault.signinattempts.category`:"success"' in query
    assert '`delivery.by`:"Bender"' in query
    assert 'labels.module:"vault-events"' in query


@pytest.mark.parametrize(
    "field, quoted",
    [
        ("process.name", "process.name"),
        ("@timestamp", "@timestamp"),
        ("1vault.category", "`1vault.category`"),
        ("vault.1category", "`vault.1category`"),
        ("process.parent-name", "`process.parent-name`"),
        ("rule.sequence", "`rule.sequence`"),
        ("any", "`any`"),
        ("rule.first", "rule.first"),
        ("odd`name", "`odd``name`"),
    ],
)
def test_eql_field_quoting(field, quoted):
    backend = eql_backend(EqlBackend)()

    assert backend.escape_and_quote_field(field) == quoted


@pytest.mark.parametrize(
    "field",
    ["process.name", "@timestamp", "_id", "a_1.b2", "user._internal", "event.metadata", "source.as"],
)
def test_esql_leaves_parsable_field_names_unquoted(field):
    backend = esql_backend(ESQLBackend)()

    assert backend.escape_and_quote_field(field) == field


@pytest.mark.parametrize(
    "field, quoted",
    [
        ("1vault.category", "`1vault.category`"),
        ("vault.1category", "`vault.1category`"),
        ("process.parent-name", "`process.parent-name`"),
        ("winlog.event_data.On", "`winlog.event_data.On`"),
        ("rule.first", "`rule.first`"),
        ("null", "`null`"),
        ("odd`name", "`odd``name`"),
    ],
)
def test_esql_quotes_field_names_it_cannot_parse(field, quoted):
    backend = esql_backend(ESQLBackend)()

    assert backend.escape_and_quote_field(field) == quoted


# ---------------------------------------------------------------------------
# Correlations
# ---------------------------------------------------------------------------

EVENT_COUNT_RULE = "tests/files/elastic/correlation_event_count.yml"
VALUE_COUNT_RULE = "tests/files/elastic/correlation_value_count.yml"
TEMPORAL_RULE = "tests/files/elastic/correlation_temporal.yml"

CORRELATION_SOURCE = "FROM logs-signin-attempts-planet-express-default METADATA _id, _index, _version"


def test_correlation_converts_to_the_correlation_query():
    """The file also holds a rule the correlation does not reference, and the
    backend emits that one first: it must not be what gets deployed"""
    query = convert("esql", EVENT_COUNT_RULE)

    assert query.splitlines() == [
        CORRELATION_SOURCE,
        '| WHERE labels.module=="vault-events" AND `1vault.signinattempts.category`=="credentials_failed"',
        "| EVAL timebucket=date_trunc(10minutes, @timestamp)",
        "| STATS event_count=count() BY timebucket, `1vault.signinattempts.target_user.email`",
        "| WHERE event_count >= 5",
    ]


def test_value_count_correlation_counts_the_mapped_field():
    query = convert("esql", VALUE_COUNT_RULE)

    assert query.splitlines()[0] == CORRELATION_SOURCE
    assert (
        "| STATS value_count=count_distinct(`1vault.signinattempts.country`)"
        " BY timebucket, `1vault.signinattempts.target_user.email`"
    ) in query
    assert query.endswith("| WHERE value_count >= 3")


def test_temporal_correlation_types_each_event():
    query = convert("esql", TEMPORAL_RULE)

    assert query.splitlines()[0] == CORRELATION_SOURCE
    assert '"vault_signin_failure"' in query and '"vault_signin_success"' in query
    assert query.endswith("| WHERE event_type_count >= 2")


def test_atomic_rule_of_a_correlated_source_keeps_the_atomic_pipelines():
    """pipelines_correlation only applies to correlation rules"""
    query = convert("esql", SIGNIN_RULE)

    assert query.startswith("FROM *-signin-attempts-planet-express-* METADATA")


def test_export_correlation_looks_back_over_its_timespan():
    """Kibana only hands the query the events between `from` and now: a
    one hour correlation run every five minutes must still see the hour"""
    rule = {**RULE_CONTENT, "correlation": {"type": "value_count", "timespan": "1h"}}

    payload = export(build_platform(), rule)

    assert payload["interval"] == "5m"
    assert payload["from"] == "now-3900s"


def test_export_correlation_look_back_adds_the_additional_look_back():
    rule = {**RULE_CONTENT, "correlation": {"type": "event_count", "timespan": "10m"}}

    payload = export(build_platform(additional_look_back="1m"), rule)

    assert payload["from"] == "now-960s"


# ---------------------------------------------------------------------------
# Deduplication metadata
# ---------------------------------------------------------------------------

def test_cleanup_adds_metadata_to_a_query_without_it():
    platform = build_platform()

    query = platform.cleanup_esql_query('FROM logs-*\n| WHERE process.name == "bender.exe"')

    assert query == 'FROM logs-* METADATA _id, _index, _version\n| WHERE process.name == "bender.exe"'


def test_cleanup_adds_metadata_even_when_a_field_is_named_version():
    """Mentioning _version in the WHERE clause is not a METADATA clause"""
    platform = build_platform()

    query = platform.cleanup_esql_query("FROM logs-* | WHERE _version > 1")

    assert query == "FROM logs-* METADATA _id, _index, _version | WHERE _version > 1"


def test_cleanup_adds_metadata_to_a_bare_source_command():
    platform = build_platform()

    assert platform.cleanup_esql_query("FROM logs-*") == "FROM logs-* METADATA _id, _index, _version"


def test_cleanup_keeps_an_existing_metadata_clause():
    platform = build_platform()
    query = "from logs-* metadata _id, _index, _version | where true"

    assert platform.cleanup_esql_query(query) == query


def test_cleanup_uses_brackets_on_legacy_esql():
    platform = build_platform(legacy_esql=True)

    query = platform.cleanup_esql_query("FROM logs-* | WHERE true")

    assert query == "FROM logs-* [METADATA _id, _index, _version] | WHERE true"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

RULE_CONTENT = {
    "title": "Successful Sign-In Of The Delivery Account",
    "id": "6f1d2c3b-8a4e-4f5d-9b6c-7d8e9f0a1b2c",
    "description": "The shared delivery account signed in successfully.",
    "author": "Hermes Conrad",
    "level": "high",
    "tags": ["attack.t1078", "attack.t1078.004", "attack.initial-access", "attack.t9999"],
    "falsepositives": ["Fry ordering pizza from the moon"],
}


def export(platform, rule_content=None, query="FROM logs-* METADATA _id, _index, _version | WHERE true"):
    """Run create_rule and return the payload sent to Kibana"""
    sent = []
    platform.kibana_import_rule = lambda json_data, rule_content: sent.append(json_data)
    platform.create_rule(dict(rule_content or RULE_CONTENT), query, "rule.yml")
    return sent[0]


def test_export_maps_a_technique_to_every_one_of_its_tactics():
    """T1078 belongs to several tactics, each with its own id"""
    threat = export(build_platform())["threat"]

    tactics = {entry["tactic"]["name"]: entry["tactic"]["id"] for entry in threat}
    assert tactics["Initial Access"] == "TA0001"
    assert tactics["Persistence"] == "TA0003"
    assert tactics["Privilege Escalation"] == "TA0004"
    assert len(set(tactics.values())) == len(tactics)


def test_export_merges_a_subtechnique_into_its_technique():
    threat = export(build_platform())["threat"]

    initial_access = next(entry for entry in threat if entry["tactic"]["id"] == "TA0001")
    assert len(initial_access["technique"]) == 1
    technique = initial_access["technique"][0]
    assert technique["id"] == "T1078"
    assert [sub["id"] for sub in technique["subtechnique"]] == ["T1078.004"]
    assert technique["subtechnique"][0]["reference"] == "https://attack.mitre.org/techniques/T1078/004"


def test_export_ignores_an_unknown_technique():
    rule = {**RULE_CONTENT, "tags": ["attack.t9999", "attack.t9999.001"]}

    assert export(build_platform(), rule)["threat"] == []


def test_export_keeps_a_tactic_without_technique():
    rule = {**RULE_CONTENT, "tags": ["attack.command-and-control"]}

    threat = export(build_platform(), rule)["threat"]

    assert threat == [
        {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": "TA0011",
                "name": "Command and Control",
                "reference": "https://attack.mitre.org/tactics/TA0011",
            },
            "technique": [],
        }
    ]


def test_export_informational_rule_is_low_with_the_lowest_risk_score():
    """Elastic has no informational severity; the risk score still tells it apart"""
    payload = export(build_platform(), {**RULE_CONTENT, "level": "informational"})

    assert payload["severity"] == "low"
    assert payload["risk_score"] == 1


def test_export_esql_rule_has_no_index():
    payload = export(build_platform())

    assert payload["type"] == "esql"
    assert payload["index"] is None


def test_export_look_back_covers_the_interval_by_default():
    payload = export(build_platform())

    assert payload["interval"] == "5m"
    assert payload["from"] == "now-5m"


def test_export_additional_look_back_widens_the_window():
    """Events ingested late are still seen by the next run"""
    payload = export(build_platform(additional_look_back="1m"))

    assert payload["interval"] == "5m"
    assert payload["from"] == "now-360s"


def test_invalid_additional_look_back_is_rejected():
    with pytest.raises(ValueError):
        build_platform(additional_look_back="a while")


def test_export_raw_rule_without_raw_language_is_a_clear_error():
    platform = ElasticPlatform(dict(ELASTIC_PARAMETERS), LOGGER_PARAM, "esql", raw=True)

    with pytest.raises(ValueError, match="raw_language"):
        export(platform)


def test_rule_changes_detect_false_positives():
    platform = build_platform()
    deployed = export(platform)
    changed = {**deployed, "false_positives": ["Leela ordering pizza"]}

    assert platform.check_rule_changes(dict(deployed), deployed) is False
    assert platform.check_rule_changes(dict(deployed), changed) is True


def test_rule_changes_detect_a_rule_no_longer_building_block():
    platform = build_platform()
    building_block = export(platform, {**RULE_CONTENT, "custom": {"building_block": True}})
    plain = export(platform)
    plain["name"] = building_block["name"]

    assert platform.check_rule_changes(building_block, plain) is True


CORRELATION_QUERY = (
    "FROM logs-* METADATA _id, _index, _version\n"
    '| WHERE `1vault.signinattempts.category`=="credentials_failed"\n'
    "| EVAL timebucket=date_trunc(10minutes, @timestamp)\n"
    "| STATS event_count=count() BY timebucket, `1vault.signinattempts.target_user.email`, host.name\n"
    "| WHERE event_count >= 5"
)
CORRELATION_CONTENT = {**RULE_CONTENT, "correlation": {"type": "event_count", "timespan": "10m"}}


def test_export_correlation_suppresses_the_alerts_of_a_group_already_raised():
    """Each run sees the bucket again: without suppression every run alerts on it"""
    payload = export(build_platform(), CORRELATION_CONTENT, CORRELATION_QUERY)

    assert payload["alert_suppression"] == {
        "group_by": ["timebucket", "1vault.signinattempts.target_user.email", "host.name"],
        "duration": {"value": 900, "unit": "s"},
        "missing_fields_strategy": "suppress",
    }


def test_export_correlation_suppression_can_be_turned_off():
    """Alert suppression needs a Platinum license"""
    payload = export(build_platform(suppress_correlation_alerts=False), CORRELATION_CONTENT, CORRELATION_QUERY)

    assert "alert_suppression" not in payload


def test_export_correlation_grouped_by_too_many_fields_is_not_suppressed():
    """Kibana suppresses on three fields at most"""
    query = CORRELATION_QUERY.replace("host.name", "host.name, source.ip, user.domain")

    payload = export(build_platform(), CORRELATION_CONTENT, query)

    assert "alert_suppression" not in payload


def test_export_atomic_rule_is_not_suppressed():
    payload = export(build_platform())

    assert "alert_suppression" not in payload


def test_rule_changes_detect_alert_suppression():
    platform = build_platform()
    suppressed = export(platform, CORRELATION_CONTENT, CORRELATION_QUERY)
    unsuppressed = {key: value for key, value in suppressed.items() if key != "alert_suppression"}

    assert platform.check_rule_changes(unsuppressed, suppressed) is True


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def test_api_key_authentication_reaches_kibana(monkeypatch):
    captured = {}

    class Response:
        status_code = 200

        def json(self):
            return {"rule_id": "6f1d2c3b"}

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr(elastic_module.requests, "get", fake_get)
    platform = build_platform(auth_method="api_key", api_key="c2NydWZmeTptb3A=")

    platform.get_rule("6f1d2c3b")

    assert captured["headers"]["Authorization"] == "ApiKey c2NydWZmeTptb3A="
    assert captured.get("auth") is None


def test_api_key_authentication_reaches_elasticsearch(monkeypatch):
    captured = {}

    class FakeElasticsearch:
        def __init__(self, hosts, **kwargs):
            captured.update(kwargs)
            self.esql = self

        def query(self, **kwargs):
            return {"values": []}

    monkeypatch.setattr(elastic_module, "Elasticsearch", FakeElasticsearch)
    platform = build_platform(auth_method="api_key", api_key="c2NydWZmeTptb3A=")

    assert platform.run_elastic_search("FROM logs-*", "esql", {}) == 0
    assert captured["api_key"] == "c2NydWZmeTptb3A="
    assert "basic_auth" not in captured


def test_unknown_authentication_method_is_rejected():
    with pytest.raises(ValueError, match="auth_method"):
        build_platform(auth_method="carrier-pigeon")


# ---------------------------------------------------------------------------
# Live cluster
# ---------------------------------------------------------------------------

LIVE_ELASTICSEARCH = os.environ.get("DROID_TEST_ELASTICSEARCH_URL")


def seed_live_cluster():
    """Index the events the live tests look for; it only needs an unsecured test node"""
    from elasticsearch import Elasticsearch

    client = Elasticsearch(LIVE_ELASTICSEARCH)
    # Both names fall under the built-in logs data stream template
    seed = client.options(ignore_status=409).index  # already seeded by a previous run
    seed(
        index="logs-signin-attempts-planet-express-default",
        id="signin-1",
        op_type="create",
        refresh=True,
        document={
            "@timestamp": "2026-11-07T12:00:00Z",
            "labels": {"module": "vault-events"},
            "delivery": {"by": "Leela"},
            "1vault": {
                "signinattempts": {
                    "category": "success",
                    "country": "Moon",
                    "target_user": {"email": "fry@planet-express.local"},
                }
            },
        },
    )
    seed(
        index="logs-endpoint.events.process-default",
        id="process-1",
        op_type="create",
        refresh=True,
        document={"@timestamp": "2026-11-07T12:00:00Z", "CommandLine": "foo.exe --deliver"},
    )

    return client


@pytest.mark.skipif(not LIVE_ELASTICSEARCH, reason="DROID_TEST_ELASTICSEARCH_URL is not set")
@pytest.mark.parametrize("rule", [SIGNIN_RULE, CORRELATION_RULE])
def test_esql_query_runs_on_a_live_cluster(rule):
    client = seed_live_cluster()

    response = client.esql.query(query=convert("esql", rule).strip())

    assert len(response["values"]) == (1 if rule == SIGNIN_RULE else 0)


LIVE_SIGN_INS = [
    # Kif fails five times, then gets in
    *[("kif@planet-express.local", "credentials_failed", "Earth", minute) for minute in range(1, 6)],
    ("kif@planet-express.local", "success", "Earth", 6),
    # Amy signs in from three planets
    ("amy@planet-express.local", "success", "Earth", 1),
    ("amy@planet-express.local", "success", "Mars", 2),
    ("amy@planet-express.local", "success", "Moon", 3),
    # Hermes fails once and gives up
    ("hermes@planet-express.local", "credentials_failed", "Earth", 4),
]


@pytest.mark.skipif(not LIVE_ELASTICSEARCH, reason="DROID_TEST_ELASTICSEARCH_URL is not set")
@pytest.mark.parametrize(
    "rule, user",
    [
        (EVENT_COUNT_RULE, "kif@planet-express.local"),
        (VALUE_COUNT_RULE, "amy@planet-express.local"),
        (TEMPORAL_RULE, "kif@planet-express.local"),
    ],
)
def test_correlation_runs_on_a_live_cluster(rule, user):
    client = seed_live_cluster()
    seed = client.options(ignore_status=409).index
    for number, (email, category, country, minute) in enumerate(LIVE_SIGN_INS):
        seed(
            index="logs-signin-attempts-planet-express-default",
            id=f"correlated-{number}",
            op_type="create",
            refresh=True,
            document={
                "@timestamp": f"2026-11-07T08:0{minute}:00Z",
                "labels": {"module": "vault-events"},
                "1vault": {
                    "signinattempts": {
                        "category": category,
                        "country": country,
                        "target_user": {"email": email},
                    }
                },
            },
        )

    response = client.esql.query(query=convert("esql", rule))

    columns = [column["name"] for column in response["columns"]]
    users = [row[columns.index("1vault.signinattempts.target_user.email")] for row in response["values"]]
    assert users == [user]


@pytest.mark.skipif(not LIVE_ELASTICSEARCH, reason="DROID_TEST_ELASTICSEARCH_URL is not set")
def test_eql_query_runs_on_a_live_cluster():
    client = seed_live_cluster()

    response = client.eql.search(
        index="logs-signin-attempts-planet-express-default", query=convert("eql", SIGNIN_RULE)
    )

    assert response["hits"]["total"]["value"] == 1
