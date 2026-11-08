"""
Module for Elastic Security
"""

import re
import time
import requests

from functools import cache
from droid.color import ColorLogger
from droid.abstracts import AbstractPlatform
from droid.platforms.common import get_search_days_ago
from requests.auth import HTTPBasicAuth
from sigma.data.mitre_attack import (
    mitre_attack_techniques,
    mitre_attack_techniques_tactics_mapping,
    mitre_attack_tactics,
)

from elasticsearch import Elasticsearch
from sigma.exceptions import SigmaConversionError

# ES|QL and EQL only parse a dotted field name unquoted when every segment
# starts with a letter (or with _ or @ followed by more) and is not a reserved
# word, which holds even for the last segment: `1password.category` and
# `delivery.by` must be backtick quoted. Reserved words checked against
# Elasticsearch 9.5.
ESQL_RESERVED_WORDS = (
    "and", "or", "not", "like", "rlike", "in", "is", "null", "true", "false",
    "first", "last", "asc", "desc", "nulls", "by", "on", "with", "where",
)
EQL_RESERVED_WORDS = (
    "and", "or", "not", "like", "regex", "in", "null", "true", "false", "by",
    "with", "where", "any", "of", "sequence", "sample", "join", "until", "maxspan",
)


def unquoted_field_pattern(reserved_words):
    """Match the field names a query language parses without backticks"""

    segment = (
        rf"(?!(?:{'|'.join(reserved_words)})(?:\.|$))"
        r"(?:[a-z][a-z0-9_]*|[_@][a-z0-9_]+)"
    )
    return re.compile(rf"^{segment}(?:\.{segment})*$", re.IGNORECASE)


ESQL_UNQUOTED_FIELD = unquoted_field_pattern(ESQL_RESERVED_WORDS)
EQL_UNQUOTED_FIELD = unquoted_field_pattern(EQL_RESERVED_WORDS)

ESQL_METADATA_FIELDS = "_id, _index, _version"

# Kibana rule actions, each one running a connector created beforehand in
# Kibana. Index and server log run on a Basic license, email and webhook
# need Gold. Default templates use the Security rule action variables.
SUMMARY_MESSAGE = (
    "{{state.signals_count}} alert(s) raised by {{context.rule.name}}.\n\n"
    "Severity: {{context.rule.severity}} (risk score {{context.rule.risk_score}})\n\n"
    "{{context.rule.description}}\n\n"
    "{{context.results_link}}"
)
ALERT_MESSAGE = (
    "{{#context.alerts}}{{kibana.alert.reason}}{{/context.alerts}}\n\n"
    "Severity: {{context.rule.severity}} (risk score {{context.rule.risk_score}})\n\n"
    "{{context.rule.description}}\n\n"
    "{{context.results_link}}"
)
SUMMARY_FIELDS = (
    '"rule_id":"{{context.rule.rule_id}}","rule_name":"{{context.rule.name}}",'
    '"severity":"{{context.rule.severity}}","risk_score":{{context.rule.risk_score}},'
    '"results_link":"{{context.results_link}}"'
)

ACTION_TYPES = {
    "index": {
        "action_type_id": ".index",
        "per_alert": True,
        "params": ("document",),
        # Nothing but the serialized alert: a string document is not JSON escaped,
        # a rule name holding a quote would break it. The alert carries the rule.
        "defaults": lambda per_alert: {
            "documents": [
                '{"alert":{{{context.alerts}}}}' if per_alert else {
                    "rule_id": "{{context.rule.rule_id}}",
                    "rule_name": "{{context.rule.name}}",
                    "severity": "{{context.rule.severity}}",
                    "risk_score": "{{context.rule.risk_score}}",
                    "alerts_count": "{{state.signals_count}}",
                    "results_link": "{{context.results_link}}",
                }
            ]
        },
    },
    "server_log": {
        "action_type_id": ".server-log",
        "per_alert": False,
        "params": ("level", "message"),
        "defaults": lambda per_alert: {
            "level": "info",
            "message": (
                "{{context.rule.name}}: {{#context.alerts}}{{kibana.alert.reason}}{{/context.alerts}}"
                if per_alert else
                "{{context.rule.name}}: {{state.signals_count}} alert(s) {{context.results_link}}"
            ),
        },
    },
    "email": {
        "action_type_id": ".email",
        "per_alert": False,
        "params": ("to", "cc", "bcc", "subject", "message"),
        "defaults": lambda per_alert: {
            "subject": "[{{context.rule.severity}}] {{context.rule.name}}",
            "message": ALERT_MESSAGE if per_alert else SUMMARY_MESSAGE,
        },
    },
    "webhook": {
        "action_type_id": ".webhook",
        "per_alert": False,
        "params": ("body",),
        # The webhook connector JSON escapes {{ }} in the body, {{{ }}} is raw
        "defaults": lambda per_alert: {
            "body": (
                "{" + SUMMARY_FIELDS + ',"alert":{{{context.alerts}}}}'
                if per_alert else
                "{" + SUMMARY_FIELDS + ',"alerts_count":{{state.signals_count}},"alerts":[{{{context.alerts}}}]}'
            )
        },
    },
}
SERVER_LOG_LEVELS = ("trace", "debug", "info", "warn", "error", "fatal")

# Kibana alert suppression: one alert per group of field values, for a
# duration or for each rule execution. Needs a Platinum license.
SUPPRESSION_MISSING_FIELDS = {"suppress": "suppress", "do_not_suppress": "doNotSuppress"}
SUPPRESSION_KEYS = ("group_by", "duration", "missing_fields")
SUPPRESSION_MAX_FIELDS = 3


def parse_suppression(spec, where):
    """Validate a suppression of the config, return Kibana's alert_suppression"""

    if not isinstance(spec, dict):
        raise ValueError(f"{where}: suppression must be a table with group_by, and optionally duration and missing_fields")

    unknown = set(spec) - set(SUPPRESSION_KEYS)
    if unknown:
        raise ValueError(
            f"{where}: unknown suppression parameters {', '.join(sorted(unknown))}, expected {', '.join(SUPPRESSION_KEYS)}"
        )

    group_by = spec.get("group_by")
    if (
        not isinstance(group_by, list)
        or not 1 <= len(group_by) <= SUPPRESSION_MAX_FIELDS
        or not all(isinstance(field, str) and field for field in group_by)
    ):
        raise ValueError(f"{where}: suppression group_by must list 1 to {SUPPRESSION_MAX_FIELDS} field names")

    missing_fields = spec.get("missing_fields", "suppress")
    if missing_fields not in SUPPRESSION_MISSING_FIELDS:
        raise ValueError(
            f"{where}: suppression missing_fields must be one of {', '.join(SUPPRESSION_MISSING_FIELDS)}"
        )

    suppression = {"group_by": list(group_by)}
    if "duration" in spec:
        match = re.fullmatch(r"(\d+)([smh])", str(spec["duration"]))
        if not match or int(match.group(1)) == 0:
            raise ValueError(f"{where}: invalid suppression duration '{spec['duration']}', e.g. 90s, 30m or 4h")
        suppression["duration"] = {"value": int(match.group(1)), "unit": match.group(2)}
    suppression["missing_fields_strategy"] = SUPPRESSION_MISSING_FIELDS[missing_fields]

    return suppression


def parse_max_signals(value, where):
    """Validate the maximum number of alerts a rule run creates"""

    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{where}: max_signals must be a positive integer, got '{value}'")

    return value


TIME_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


@cache
def esql_backend(backend_class):
    """Wrap the ES|QL backend so its queries parse and read like Elastic's own

    The backend leaves field names such as `1password.category` unquoted, which
    Elasticsearch refuses to parse, and writes the whole pipeline in lower case
    on one line. The wrapper quotes what ES|QL cannot parse and renders
    `FROM … METADATA …` followed by one upper-case command per line.
    """

    class DroidESQLBackend(backend_class):
        field_quote_pattern = ESQL_UNQUOTED_FIELD
        field_escape = "`"  # a backtick inside a quoted name is doubled

        and_token = "AND"
        or_token = "OR"
        not_token = "NOT"
        wildcard_match_expression = "{field} LIKE {value}"
        re_expression = '{field} RLIKE "{regex}"'
        field_null_expression = "{field} IS NULL"
        field_exists_expression = "{field} IS NOT NULL"
        field_not_exists_expression = "{field} IS NULL"
        or_in_operator = "IN"

        correlation_search_multi_rule_query_expression_joiner = " OR "
        typing_expression = "| EVAL event_type=case({queries})"
        event_count_aggregation_expression = {
            "stats": "| EVAL timebucket=date_trunc({timespan}, @timestamp)\n"
                     "| STATS event_count=count(){fields}{groupby}"
        }
        value_count_aggregation_expression = {
            "stats": "| EVAL timebucket=date_trunc({timespan}, @timestamp)\n"
                     "| STATS value_count=count_distinct({field}){fields}{groupby}"
        }
        temporal_aggregation_expression = {
            "stats": "| EVAL timebucket=date_trunc({timespan}, @timestamp)\n"
                     "| STATS event_type_count=count_distinct(event_type){fields}{groupby}"
        }
        groupby_expression_nofield = {"stats": " BY timebucket"}
        groupby_expression = {"stats": " BY timebucket{fields}"}
        event_count_condition_expression = {"stats": "| WHERE event_count {op} {count}"}
        value_count_condition_expression = {"stats": "| WHERE value_count {op} {count}"}
        temporal_condition_expression = {"stats": "| WHERE event_type_count {op} {count}"}

        def finalize_query_default(self, rule, query, index, state):
            metadata = state.processing_state.get("metadata", self.state_defaults["metadata"])
            index_state = state.processing_state.get("index", self.state_defaults["index"])

            return f"FROM {index_state} METADATA {metadata}\n| WHERE {query}"

    return DroidESQLBackend


@cache
def eql_backend(backend_class):
    """Wrap the EQL backend so it quotes every field name EQL cannot parse

    The backend only quotes a name starting with a digit or holding a space or
    a dash, which leaves out `vault.1category` and reserved words like `by`.
    It also falls back on droid's default index, logs-*.
    """

    class DroidEqlBackend(backend_class):
        field_quote_pattern = EQL_UNQUOTED_FIELD
        field_quote_pattern_negation = True
        field_escape = "`"  # a backtick inside a quoted name is doubled

        def __init__(self, *args, **kwargs):
            # A rule whose pipelines set no index reads logs-*, rather than the
            # beats and APM indices the backend falls back on
            kwargs.setdefault("index_names", ["logs-*"])
            super().__init__(*args, **kwargs)

    return DroidEqlBackend


def time_to_seconds(value, unit=None) -> int:
    """Convert "5m", or 5 with the unit "m", into seconds"""

    match = re.fullmatch(r"(\d+)\s*([smhdw])?", f"{value}{unit or ''}".strip())
    if not match or not match.group(2):
        raise ValueError(f"Invalid duration: '{value}{unit or ''}' (expected e.g. 90s, 5m, 1h or 1d)")

    return int(match.group(1)) * TIME_UNIT_SECONDS[match.group(2)]


class ElasticPlatform(AbstractPlatform):

    def __init__(
        self, parameters: dict, logger_param: bool,
        language: str, raw: bool=False) -> None:

        super().__init__(name="Elastic")

        self._parameters = parameters

        self.logger = ColorLogger(__name__, **logger_param)

        if "kibana_url" not in self._parameters:
            raise ValueError("ElasticPlatform: 'kibana_url' is not set.")

        if "elastic_hosts" not in self._parameters:
            self.logger.error(
                "ElasticPlatform: 'elastic_hosts' is not set. Searching will not be available"
            )
            self._parameters["elastic_hosts"] = []
        elif not isinstance(self._parameters["elastic_hosts"], list):
            self._parameters["elastic_hosts"] = [self._parameters["elastic_hosts"]]
        if "elastic_ca" not in self._parameters:
            self._parameters["elastic_ca"] = None
        if "elastic_tls_verify" not in self._parameters:
            self._parameters["elastic_tls_verify"] = False
            self.logger.warning(
                "ElasticPlatform: 'elastic_tls_verify' is not set. Defaulting to not verifying TLS"
            )

        if "kibana_ca" not in self._parameters:
            self._parameters["kibana_ca"] = False
        if "tls_verify" not in self._parameters:
            self._parameters["tls_verify"] = True

        if "schedule_interval" not in self._parameters:
            self.logger.debug(
                "ElasticPlatform: 'schedule_interval' is not set, using default of 1."
            )
            self._parameters["schedule_interval"] = "1"

        if "schedule_interval_unit" not in self._parameters:
            self.logger.debug(
                "ElasticPlatform: 'schedule_interval_unit' is not set, using default of h."
            )
            self._parameters["schedule_interval_unit"] = "h"

        if "license" not in self._parameters:
            self.logger.debug("ElasticPlatform: 'license' is not set, using default of DRL.")
            self._parameters["license"] = "DRL"

        if "eql_search_range_gte" not in self._parameters:
            self.logger.debug(
                "ElasticPlatform: 'eql_search_range_gte' is not set, using default of 24h."
            )
            self._parameters["eql_search_range_gte"] = "now-24h"
        if "esql_search_range_gte" not in self._parameters:
            self.logger.debug(
                "ElasticPlatform: 'esql_search_range_gte' is not set, using default of 1h."
            )
            self._parameters["esql_search_range_gte"] = "now-1h"

        if "legacy_esql" not in self._parameters:
            self.logger.debug(
                "ElasticPlatform: 'legacy_esql' is not set, using default of False."
            )
            self._parameters["legacy_esql"] = False

        self._eql_search_range_gte = self._parameters["eql_search_range_gte"]
        self._esql_search_range_gte = self._parameters["esql_search_range_gte"]
        self._schedule_interval = self._parameters["schedule_interval"]
        self._schedule_interval_unit = self._parameters["schedule_interval_unit"]
        self._license = self._parameters["license"]
        self._kibana_url = self._parameters["kibana_url"]
        self._elastic_hosts = self._parameters["elastic_hosts"]
        self._kibana_ca = self._parameters["kibana_ca"]
        self._tls_verify = self._parameters["tls_verify"]
        self._elastic_ca = self._parameters["elastic_ca"]
        self._elastic_tls_verify = self._parameters["elastic_tls_verify"]
        self._legacy_esql = self._parameters["legacy_esql"]
        self._language = language
        self._raw = raw
        self._index_name = None  # resolved while converting an EQL rule

        # Extra look-back so an event ingested after the previous run is not missed
        self._additional_look_back = self._parameters.get("additional_look_back")
        self._additional_look_back_seconds = (
            time_to_seconds(self._additional_look_back) if self._additional_look_back else 0
        )

        self._actions = {
            name: self.build_action(name, action)
            for name, action in (self._parameters.get("actions") or {}).items()
        }

        # Alert suppression needs a Platinum license
        self._suppress_correlation_alerts = self._parameters.get("suppress_correlation_alerts", True)
        self._suppression = None
        if "suppression" in self._parameters:
            self._suppression = parse_suppression(self._parameters["suppression"], "ElasticPlatform")
        # Fail before any export on a pipeline group suppression that Kibana would refuse
        for group, group_config in (self._parameters.get("pipelines") or {}).items():
            if isinstance(group_config, dict) and "suppression" in group_config:
                parse_suppression(group_config["suppression"], f"ElasticPlatform: pipeline group '{group}'")

        self._max_signals = parse_max_signals(self._parameters.get("max_signals", 100), "ElasticPlatform")

        self._auth_method = self._parameters.get("auth_method", "basic")
        if self._auth_method == "basic":
            self._username = self._parameters.get("username")
            self._password = self._parameters.get("password")
        elif self._auth_method == "api_key":
            self._api_key = self._parameters.get("api_key")
        else:
            raise ValueError(
                f"ElasticPlatform: unsupported 'auth_method' '{self._auth_method}', use 'basic' or 'api_key'."
            )

        if "alert_prefix" in self._parameters:
            self._alert_prefix = self._parameters["alert_prefix"]
        else:
            self._alert_prefix = None

        if "building_block_prefix" in self._parameters:
            self._building_block_prefix = self._parameters["building_block_prefix"]
        else:
            self._building_block_prefix = "BB"

        if self._kibana_ca:
            self._tls_verified = self._kibana_ca
        else:
            self._tls_verified = self._tls_verify

    def level_parser(self, level):
        level = level.lower()
        if level == "critical":
            return 99
        elif level == "high":
            return 73
        elif level == "medium":
            return 47
        elif level == "low":
            return 21
        elif level == "informational":
            return 1
        else:
            return 100

    def mitre_attack_threats(self, tags):
        """Build the Elastic `threat` list from the ATT&CK tags of a rule

        Elastic groups techniques under their tactic: a technique belonging to
        several tactics appears under each of them, and a subtechnique is nested
        in its technique. A tactic tag without technique keeps its own entry.
        """

        tactic_ids = {name: tactic_id for tactic_id, name in mitre_attack_tactics.items()}
        threats = {}  # tactic id -> threat entry

        def tactic_entry(tactic_id):
            if tactic_id not in threats:
                name = mitre_attack_tactics[tactic_id]
                threats[tactic_id] = {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": tactic_id,
                        "name": " ".join(
                            word if word == "and" else word.capitalize() for word in name.split("-")
                        ),
                        "reference": f"https://attack.mitre.org/tactics/{tactic_id}",
                    },
                    "technique": [],
                }
            return threats[tactic_id]

        for tag in tags:
            name = tag.lower().removeprefix("attack.").replace("_", "-")

            if name.upper() in mitre_attack_tactics:
                tactic_entry(name.upper())
                continue
            if name in tactic_ids:
                tactic_entry(tactic_ids[name])
                continue

            match = re.fullmatch(r"(t\d{4})(?:\.(\d{3}))?", name)
            if not match or match.group(1).upper() not in mitre_attack_techniques:
                continue

            technique_id = match.group(1).upper()
            subtechnique_id = f"{technique_id}.{match.group(2)}" if match.group(2) else None
            if subtechnique_id and subtechnique_id not in mitre_attack_techniques:
                self.logger.warning(f"Unknown ATT&CK subtechnique '{subtechnique_id}', mapping {technique_id} only")
                subtechnique_id = None

            for tactic_name in mitre_attack_techniques_tactics_mapping.get(technique_id, []):
                if tactic_name not in tactic_ids:
                    continue
                techniques = tactic_entry(tactic_ids[tactic_name])["technique"]

                technique = next((t for t in techniques if t["id"] == technique_id), None)
                if technique is None:
                    technique = {
                        "id": technique_id,
                        "name": mitre_attack_techniques[technique_id],
                        "reference": f"https://attack.mitre.org/techniques/{technique_id}",
                        "subtechnique": [],
                    }
                    techniques.append(technique)

                if subtechnique_id and all(s["id"] != subtechnique_id for s in technique["subtechnique"]):
                    technique["subtechnique"].append({
                        "id": subtechnique_id,
                        "name": mitre_attack_techniques[subtechnique_id],
                        "reference": "https://attack.mitre.org/techniques/" + subtechnique_id.replace(".", "/"),
                    })

        for threat in threats.values():
            for technique in threat["technique"]:
                if not technique["subtechnique"]:
                    del technique["subtechnique"]

        return list(threats.values())

    def get_index_name(self, converted_rule):
        """Take the index the pipelines resolved while converting the rule

        pySigma applies every `set_state` of the index in priority order, with
        or without rule conditions, so its processing state is the only
        authority on which index an EQL rule reads.
        """

        index = None
        try:
            states = converted_rule.get_conversion_states() if converted_rule else []
        except SigmaConversionError:
            states = []
        for state in states:
            index = state.processing_state.get("index")
            if index:
                break

        if not index:
            self.logger.warning("No index set by the pipelines of the rule, using default index 'logs-*'")
            self._index_name = ["logs-*"]
            return

        indices = []
        pending = [index]
        while pending:
            value = pending.pop(0)
            if isinstance(value, list):
                pending = value + pending
            elif isinstance(value, str):
                indices += [name.strip() for name in value.split(",") if name.strip()]
            else:
                raise ValueError(f"Index name in pipeline is malformed: {index}")

        self.logger.info(f"The value of the key 'index' is: {indices}")
        self._index_name = indices

    def raw_index(self, rule_content):
        """Return the index a raw EQL rule reads, its custom index or logs-*"""

        index = rule_content.get("custom", {}).get("index", "logs-*")
        return [index] if isinstance(index, str) else index

    def kibana_request(self, method, **kwargs):
        """Send a request to the Kibana detection engine rules API"""

        headers = {"kbn-xsrf": "true", **kwargs.pop("headers", {})}
        if self._auth_method == "api_key":
            headers["Authorization"] = f"ApiKey {self._api_key}"
            auth = None
        else:
            auth = HTTPBasicAuth(self._username, self._password)

        return getattr(requests, method)(
            self._kibana_url + "/api/detection_engine/rules",
            headers=headers,
            verify=self._tls_verified,
            auth=auth,
            **kwargs,
        )

    def elastic_client(self):
        """Build an Elasticsearch client authenticated like Kibana requests"""

        if self._auth_method == "api_key":
            credentials = {"api_key": self._api_key}
        else:
            credentials = {"basic_auth": (self._username, self._password)}

        return Elasticsearch(
            self._elastic_hosts,
            verify_certs=self._elastic_tls_verify,
            ca_certs=self._elastic_ca,
            request_timeout=300,
            max_retries=3,
            **credentials,
        )

    def remove_rule(self, rule_content, rule_converted=None, rule_file=None):
        """Remove an analytic rule in Elastic, a rule already gone included"""
        response = self.kibana_request("delete", params={"rule_id": rule_content["id"]})
        if response.status_code == 200:
            return response.json()
        if response.status_code == 404:
            self.logger.info(f"Rule {rule_content['id']} is already absent from Kibana")
            return None
        raise Exception(response.text)

    def get_rule(self, rule_id):
        """Return a rule, False when Kibana does not have it

        Any other refusal, such as a missing privilege, is an error: taking it
        for an absent rule would have export create the rule again.
        """
        response = self.kibana_request("get", params={"rule_id": rule_id})
        if response.status_code == 200:
            return response.json()
        if response.status_code == 404:
            return False
        raise Exception(response.text)

    def check_rule_changes(self, existing_rule, new_rule):
        fields = [
            "name",
            "description",
            "query",
            "language",
            "severity",
            "risk_score",
            "threat",
            "tags",
            "enabled",
            "interval",
            "author",
            "from",
            "to",
            "license",
            "actions",
            # Optional: a value dropped from the rule must be dropped on Kibana too
            "false_positives",
            "references",
            "building_block_type",
            "alert_suppression",
            "max_signals",
        ]
        if new_rule.get("index"):
            fields.append("index")
        # Kibana gives every action a uuid of its own
        existing_rule = {
            **existing_rule,
            "actions": [
                {key: value for key, value in action.items() if key != "uuid"}
                for action in existing_rule.get("actions") or []
            ],
        }
        for field in fields:
            # Kibana returns empty lists for optional list fields never set
            if (existing_rule.get(field) or None) != (new_rule.get(field) or None):
                self.logger.info(f"Rule '{new_rule['name']}' has changed")
                return True
        self.logger.info(f"Rule '{new_rule['name']}' already exists and is up to date")
        return False

    def kibana_import_rule(self, json_data, rule_content):
        existing_rule = self.get_rule(json_data["rule_id"])
        if existing_rule and existing_rule["language"] != json_data["language"]:
            self.remove_rule(rule_content)
            self.logger.warning(
                f"Rule '{json_data['name']}' already existed in different language. It was recreated with the new language"
            )
            existing_rule = False
        if existing_rule:
            if self.check_rule_changes(existing_rule, json_data):
                response = self.kibana_request("put", params={"overwrite": "true"}, json=json_data)
            else:
                return True
        else:
            response = self.kibana_request("post", json=json_data)

        if response.status_code == 200:
            return True
        else:
            raise Exception(response.text)

    def cleanup_esql_query(self, query):
        """Add the METADATA clause Elastic needs to deduplicate alerts

        A non-aggregating ES|QL rule must read `_id, _index, _version` in its
        source command, e.g. `FROM logs-* METADATA _id, _index, _version`.
        https://www.elastic.co/guide/en/security/current/rules-ui-create.html#esql-non-agg-query-dedupe
        """
        lowerquery = query.lower()
        # Ignore Correlation Rules because they already deduplicate themselves
        if "stats " in lowerquery and " by " in lowerquery:
            return query

        # The source command runs up to the first pipe
        source_command = query.split("|", 1)[0]
        if re.search(r"\bmetadata\b", source_command, re.IGNORECASE):
            return query

        # Older Elastic versions need brackets around the METADATA clause and
        # newer ones deprecated them, hence the legacy_esql flag
        if self._legacy_esql:
            clause = f"[METADATA {ESQL_METADATA_FIELDS}]"
        else:
            clause = f"METADATA {ESQL_METADATA_FIELDS}"

        source = source_command.rstrip()
        rest = query[len(source):]
        if rest and not rest[0].isspace():
            rest = " " + rest

        return f"{source} {clause}{rest}"

    @staticmethod
    def build_action(name, action):
        """Build the Kibana rule action of an `actions` entry of the config"""

        action = dict(action)
        action_type = ACTION_TYPES.get(action.pop("type", None))
        if action_type is None:
            raise ValueError(f"ElasticPlatform: action '{name}' needs a type among {', '.join(ACTION_TYPES)}")

        connector_id = action.pop("connector_id", None)
        if not connector_id:
            raise ValueError(f"ElasticPlatform: action '{name}' needs the connector_id of a Kibana connector")

        per_alert = action.pop("per_alert", action_type["per_alert"])
        throttle = action.pop("throttle", None)
        if throttle is not None:
            if per_alert:
                raise ValueError(f"ElasticPlatform: action '{name}' can only throttle a summary, set per_alert = false")
            if not re.fullmatch(r"\d+[smhd]", str(throttle)):
                raise ValueError(f"ElasticPlatform: action '{name}' has an invalid throttle '{throttle}', e.g. 1h")

        unknown = set(action) - set(action_type["params"])
        if unknown:
            raise ValueError(
                f"ElasticPlatform: action '{name}' has unknown parameters {', '.join(sorted(unknown))}, "
                f"expected {', '.join(action_type['params'])}"
            )

        params = action_type["defaults"](per_alert)
        if "document" in action:
            params["documents"] = [action.pop("document")]
        params.update(action)

        if action_type["action_type_id"] == ".email" and not any(params.get(key) for key in ("to", "cc", "bcc")):
            raise ValueError(f"ElasticPlatform: action '{name}' needs recipients in to, cc or bcc")
        if action_type["action_type_id"] == ".server-log" and params["level"] not in SERVER_LOG_LEVELS:
            raise ValueError(
                f"ElasticPlatform: action '{name}' has an invalid level '{params['level']}', "
                f"expected {', '.join(SERVER_LOG_LEVELS)}"
            )

        return {
            "group": "default",
            "id": connector_id,
            "action_type_id": action_type["action_type_id"],
            "params": params,
            "frequency": {
                "summary": not per_alert,
                "notifyWhen": "onThrottleInterval" if throttle else "onActiveAlert",
                "throttle": throttle,
            },
        }

    def rule_actions(self, rule_content):
        """Return the actions of a rule, all of them unless it selects some"""

        selected = rule_content.get("custom", {}).get("elastic_actions")
        if selected is None:
            return list(self._actions.values())

        unknown = [name for name in selected if name not in self._actions]
        if unknown:
            raise ValueError(f"Unknown Elastic actions {', '.join(unknown)} in custom.elastic_actions")

        return [self._actions[name] for name in selected]

    def rule_suppression(self, rule_content, rule_file):
        """Resolve the alert suppression a rule asks for

        The rule's own `elastic_suppression` wins, then the one of its pipeline
        group, then the platform one. `elastic_suppression: false` opts out.

        Return: Kibana's alert_suppression, None when nothing is configured, or
        False when the rule opts out
        """

        custom = rule_content.get("custom", {})
        if "elastic_suppression" in custom:
            if custom["elastic_suppression"] is False:
                return False
            return parse_suppression(custom["elastic_suppression"], f"Rule {rule_file}")

        group_config = rule_content.get("_droid_variant", {}).get("config", {})
        if "suppression" in group_config:
            return parse_suppression(group_config["suppression"], f"Rule {rule_file}")

        return dict(self._suppression) if self._suppression else None

    @staticmethod
    def correlation_group_by(query):
        """Return the fields the aggregation of an ES|QL correlation groups by"""

        stats = [line for line in query.splitlines() if line.startswith("| STATS ")]
        if not stats or " BY " not in stats[-1]:
            return []

        fields = stats[-1].rsplit(" BY ", 1)[1].split(", ")
        return [
            field[1:-1].replace("``", "`") if field.startswith("`") else field
            for field in fields
        ]

    def create_rule(self, rule_content, rule_converted, rule_file):
        """Create an analytic rule in Elastic
        Create a scheduled alert rule in Elastic
        """

        rule_tags = rule_content.get("tags") or []
        threat = self.mitre_attack_threats([tag for tag in rule_tags if tag.startswith("attack.")])
        tags = [tag for tag in rule_tags if not tag.startswith("attack.")]

        # Elastic has no informational severity, the risk score still tells it apart
        risk_score = self.level_parser(rule_content["level"])
        severity = rule_content["level"]
        if severity == "informational":
            severity = "low"
        author = rule_content["author"]
        if isinstance(author, str):
            author = [author]

        if rule_content.get("custom", {}).get("building_block") is True:
            building_block = True

        else:
            building_block = False

        # Handling the display name
        if self._alert_prefix:
            display_name = self._alert_prefix + " - " + rule_content["title"]
        else:
            display_name = rule_content["title"]
        if building_block:
            display_name = self._building_block_prefix + " - " + display_name
        # Handling the status of the alert

        if rule_content.get("custom", {}).get("disabled") is True:
            enabled = False
            self.logger.info(f"Successfully disabled the rule {rule_file}")
        else:
            enabled = True

        language = self._language
        if "custom" in rule_content and "raw_language" in rule_content["custom"]:
            language = rule_content["custom"]["raw_language"]
        elif self._raw:
            raise ValueError(
                f"Raw rule {rule_file} needs the custom parameter 'raw_language' to be set"
            )

        if language == "esql":
            self._index_name = None
            rule_converted = self.cleanup_esql_query(rule_converted)

        if language == "eql" and self._raw:
            self._index_name = self.raw_index(rule_content)


        max_signals = self._max_signals
        if "elastic_max_signals" in rule_content.get("custom", {}):
            max_signals = parse_max_signals(rule_content["custom"]["elastic_max_signals"], f"Rule {rule_file}")

        interval = f"{self._schedule_interval}{self._schedule_interval_unit}"
        extra_look_back = self._additional_look_back_seconds
        # Kibana only hands the query the events since `from`: a correlation
        # must see its whole timespan, whichever bucket the run falls in
        timespan = (rule_content.get("correlation") or {}).get("timespan")
        if timespan:
            extra_look_back += time_to_seconds(timespan)
        look_back_seconds = (
            time_to_seconds(self._schedule_interval, self._schedule_interval_unit) + extra_look_back
        )
        if extra_look_back:
            look_back = f"now-{look_back_seconds}s"
        else:
            look_back = f"now-{interval}"

        # Build the json_data for kibana import
        json_data = {
            "name": display_name,
            "enabled": enabled,
            "interval": interval,
            "author": author,
            "description": rule_content["description"],
            "rule_id": rule_content["id"],
            "from": look_back,
            "immutable": False,
            "license": self._license,
            "output_index": "",  # TODO: Check if there should be a parameter for this
            "meta": {"from": self._additional_look_back or "5m"},  # look-back shown by Kibana
            "max_signals": max_signals,
            "risk_score": risk_score,
            "risk_score_mapping": [],  # TODO: Check if this should be configurable
            "severity": severity,
            "severity_mapping": [],  # TODO: Check if this should be configurable
            "threat": threat,
            "tags": tags,
            "to": "now",
            "version": 1,  # TODO: Check if this actually matters
            "exceptions_list": [],
            "related_integrations": [],
            "required_fields": [],
            "setup": "",
            "type": language,
            "language": language,
            "index": self._index_name,
            "query": rule_converted,
            "filters": [],
            "actions": self.rule_actions(rule_content),
        }

        # TODO: It might be a good idea to add more optional fields
        if "references" in rule_content:
            json_data["references"] = rule_content["references"]
        if building_block:
            json_data["building_block_type"] = "default"
        if "falsepositives" in rule_content:
            json_data["false_positives"] = rule_content["falsepositives"]

        # An aggregating query has no _id to deduplicate on, and every run
        # within the look-back sees the same bucket again: suppress the alerts
        # of a group already raised for as long as a run can see it
        suppression = self.rule_suppression(rule_content, rule_file)
        correlation = language == "esql" and timespan
        if suppression:
            if correlation:
                suppression.setdefault("duration", {"value": look_back_seconds, "unit": "s"})
                returned = self.correlation_group_by(rule_converted)
                not_returned = [field for field in suppression["group_by"] if field not in returned]
                if returned and not_returned:
                    self.logger.warning(
                        f"Correlation {rule_file} suppresses on {', '.join(not_returned)}, which it does not "
                        f"return: its alerts only hold {', '.join(returned)}"
                    )
            json_data["alert_suppression"] = suppression
        elif suppression is None and correlation and self._suppress_correlation_alerts:
            group_by = self.correlation_group_by(rule_converted)
            if len(group_by) > SUPPRESSION_MAX_FIELDS:
                self.logger.warning(
                    f"Correlation {rule_file} groups by more than the {SUPPRESSION_MAX_FIELDS} fields Kibana "
                    "can suppress on, each run will raise its alerts again: pick the fields to suppress on "
                    "with custom.elastic_suppression"
                )
            elif group_by:
                json_data["alert_suppression"] = {
                    "group_by": group_by,
                    "duration": {"value": look_back_seconds, "unit": "s"},
                    "missing_fields_strategy": "suppress",
                }

        try:
            self.kibana_import_rule(json_data, rule_content)
            self.logger.info(
                f"Successfully exported the rule {rule_file}",
                extra={
                    "rule_file": rule_file,
                    "rule_converted": rule_converted,
                    "rule_content": rule_content,
                },
            )
        except Exception as e:
            self.logger.error(
                f"Could not export the rule {rule_file} - error: {e}",
                extra={
                    "rule_file": rule_file,
                    "rule_converted": rule_converted,
                    "rule_content": rule_content,
                    "error": e,
                },
            )
            raise

    def run_eql_search(self, query, es_client=None, index=None, range_gte=None):
        response = es_client.eql.search(
            index=index,
            query=query,
            wait_for_completion_timeout=0,
            size=100,
            filter={"range": {"@timestamp": {"gte": range_gte or self._eql_search_range_gte}}},
        )
        search_id = response["id"]
        try:
            # Waiting on its own search through the get API needs no cluster
            # privilege, unlike the status API
            while response.get("is_running"):
                self.logger.debug(f"Query {search_id} is still running")
                response = es_client.eql.get(id=search_id, wait_for_completion_timeout="10s")
        finally:
            # Left behind, an async search is kept for five days
            es_client.eql.delete(id=search_id)
        self.logger.debug(f"Query {search_id} is done")

        if "hits" in response:
            return response["hits"]["total"]["value"]
        return None

    def run_esql_search(self, query, es_client=None, range_gte=None):
        # Count on the cluster: the rows returned stop at the default LIMIT 1000
        response = es_client.esql.query(
            query=f"{query}\n| STATS droid_hits = COUNT(*)",
            filter={"range": {"@timestamp": {"gte": range_gte or self._esql_search_range_gte}}},
        )
        values = response.get("values") or [[0]]
        return values[0][0]

    def run_elastic_search(self, rule_converted, language=None, rule_content=None):

        es_client = self.elastic_client()

        index = self._index_name
        if rule_content and "custom" in rule_content and "raw_language" in rule_content["custom"]:
            language = rule_content["custom"]["raw_language"]
        if self._raw and language == "eql":
            index = self.raw_index(rule_content)
        self.logger.debug(f"Searching with the {language} language")
        # A rule lookback is expressed in days, which Elastic takes as date math
        days_ago = get_search_days_ago(rule_content, None, self.logger)
        range_gte = f"now-{days_ago}d" if days_ago else None

        if language == "esql":
            return self.run_esql_search(rule_converted, es_client=es_client, range_gte=range_gte)
        elif language == "eql":
            return self.run_eql_search(
                rule_converted, es_client=es_client, index=index, range_gte=range_gte
            )
        else:
            raise ValueError(f"Unsupported language: {language}")