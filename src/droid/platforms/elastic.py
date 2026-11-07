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
    """

    class DroidEqlBackend(backend_class):
        field_quote_pattern = EQL_UNQUOTED_FIELD
        field_quote_pattern_negation = True
        field_escape = "`"  # a backtick inside a quoted name is doubled

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

        # Alert suppression needs a Platinum license
        self._suppress_correlation_alerts = self._parameters.get("suppress_correlation_alerts", True)

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

    def get_index_name(self, pipeline, rule_content):
        index_value = "logs-*"
        index_found = False

        if "logsource" in rule_content:
            matchlist = ["category", "custom_attributes", "product", "service", "source"]
            matchlength = sum(1 for x in rule_content["logsource"] if x in matchlist)

            for item in pipeline.items:
                if (
                    hasattr(item, "transformation")
                    and hasattr(item.transformation, "key")
                    and hasattr(item.transformation, "val")
                    and item.transformation.key == "index"
                ):
                    matches = 0

                    for rule_condition in item.transformation.processing_item.rule_conditions:
                        for key, value in rule_content["logsource"].items():
                            if key in matchlist:
                                condition_value = getattr(rule_condition.logsource, key, None)
                                if condition_value is None or condition_value == value:
                                    matches += 1

                    if matches == matchlength:
                        index_value = item.transformation.val
                        self.logger.info(f"The value of the key 'index' is: {index_value}")
                        index_found = True
                        break
        else:
            self.logger.warning("No logsource found in the rule, using default index 'logs-*'")

        if not index_found:
            self.logger.warning("No index value found for the rule, using default index 'logs-*'")

        if isinstance(index_value, str):
            self._index_name = [index_value]
        elif isinstance(index_value, list):
            self._index_name = index_value
        else:
            self.logger.error("Index name in pipeline is missing or malformed")
            raise ValueError("Index name in pipeline is missing or malformed")

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
        """Remove an analytic rule in Elastic"""
        response = self.kibana_request("delete", params={"rule_id": rule_content["id"]})
        if response.status_code == 200:
            return response.json()
        else:
            return False

    def get_rule(self, rule_id):
        response = self.kibana_request("get", params={"rule_id": rule_id})
        if response.status_code == 200:
            return response.json()
        else:
            return False

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
        ]
        if new_rule.get("index"):
            fields.append("index")
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
            self._index_name = ["logs-*"]

        if language == "eql" and self._raw and "custom" in rule_content and "index" in rule_content["custom"]:
            if isinstance(rule_content["custom"]["index"], str):
                self._index_name = [rule_content["custom"]["index"]]
            else:
                self._index_name = rule_content["custom"]["index"]


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
            "max_signals": 100,  # TODO: Check if there should be a parameter for this
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
            "actions": [],
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
        if language == "esql" and timespan and self._suppress_correlation_alerts:
            group_by = self.correlation_group_by(rule_converted)
            if len(group_by) > 3:
                self.logger.warning(
                    f"Correlation {rule_file} groups by more than the 3 fields Kibana can suppress on, "
                    "each run will raise its alerts again"
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
                f"Could not export the rule {rule_file}",
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
        es_client.eql.get_status(id=search_id)
        while es_client.eql.get_status(id=search_id)["is_running"]:
            self.logger.debug(f"Query {search_id} is still running")
            # print(es_client.eql.get_status(id=search_id))
            time.sleep(10)
        self.logger.debug(f"Query {search_id} is done")
        results = es_client.eql.get(id=search_id)
        es_client.eql.delete(id=search_id)
        if "hits" in results:
            return results["hits"]["total"]["value"]
        else:
            return None

    def run_esql_search(self, query, es_client=None, range_gte=None):
        response = es_client.esql.query(
            query=query,
            filter={"range": {"@timestamp": {"gte": range_gte or self._esql_search_range_gte}}},
        )
        return len(response.get("values", []))

    def run_elastic_search(self, rule_converted, language=None, rule_content=None):

        es_client = self.elastic_client()

        index = self._index_name
        if rule_content and "custom" in rule_content and "raw_language" in rule_content["custom"]:
            language = rule_content["custom"]["raw_language"]
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