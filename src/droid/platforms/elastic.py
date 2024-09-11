"""
Module for Elastic Security
"""

import re
import time
import requests

from droid.color import ColorLogger
from droid.abstracts import AbstractPlatform
from requests.auth import HTTPBasicAuth
from sigma.data.mitre_attack import (
    mitre_attack_techniques,
    mitre_attack_techniques_tactics_mapping,
    mitre_attack_tactics,
)

from elasticsearch import Elasticsearch

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

        if self._parameters["auth_method"] == "basic":
            self._username = self._parameters["username"]
            self._password = self._parameters["password"]

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

    def mitre_attack_parser(self, tag):
        tag = tag.replace("attack.", "")
        subtechnique = None
        if tag.startswith("ta"):
            return None
        if tag.startswith("t"):
            technique = tag.upper()
            if "." in technique:  # Subtechnique
                subtechnique = technique
                technique = technique.split(".")[0]
            if technique in mitre_attack_techniques:
                threats = []
                technique_name = mitre_attack_techniques[technique]
                if subtechnique:
                    subtechnique_name = mitre_attack_techniques[subtechnique]
                tactic_names = mitre_attack_techniques_tactics_mapping[technique]
                for tactic in mitre_attack_tactics:
                    if mitre_attack_tactics[tactic] in tactic_names:
                        tactic_id = tactic
                for tactic_name in tactic_names:
                    tactic = {
                        "tactic": {
                            "id": tactic_id,
                            "reference": f"https://attack.mitre.org/tactics/{tactic_id}",
                            "name": tactic_name.title().replace("-", " "),
                        }
                    }
                    if subtechnique:
                        x, y = subtechnique.split(".")
                        technique = {
                            "technique": [
                                {
                                    "id": technique,
                                    "reference": f"https://attack.mitre.org/techniques/{technique}",
                                    "name": technique_name,
                                    "subtechnique": [
                                        {
                                            "id": subtechnique,
                                            "reference": f"https://attack.mitre.org/techniques/{x}/{y}",
                                            "name": subtechnique_name,
                                        }
                                    ],
                                }
                            ]
                        }
                    else:
                        technique = {
                            "technique": [
                                {
                                    "id": technique,
                                    "reference": f"https://attack.mitre.org/techniques/{technique}",
                                    "name": technique_name,
                                }
                            ]
                        }
                    threat = {
                        **tactic,
                        "framework": "MITRE ATT&CK",
                        **technique,
                    }
                    threats.append(threat)
                    return threats
        return None

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

    def remove_rule(self, rule_content, rule_converted=None, rule_file=None):
        """Remove an analytic rule in Elastic"""
        params = {
            "rule_id": rule_content["id"],
        }
        headers = {
            "kbn-xsrf": "true",
        }
        response = requests.delete(
            self._kibana_url + "/api/detection_engine/rules",
            params=params,
            headers=headers,
            verify=self._tls_verified,
            auth=HTTPBasicAuth(self._username, self._password),
        )
        if response.status_code == 200:
            return response.json()
        else:
            return False

    def get_rule(self, rule_id):
        params = {
            "rule_id": rule_id,
        }
        headers = {
            "kbn-xsrf": "true",
        }
        response = requests.get(
            self._kibana_url + "/api/detection_engine/rules",
            params=params,
            headers=headers,
            verify=self._tls_verified,
            auth=HTTPBasicAuth(self._username, self._password),
        )
        if response.status_code == 200:
            return response.json()
        else:
            return False

    def check_rule_changes(self, existing_rule, new_rule):
        try:
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
                "actions"
            ]
            if new_rule["index"]:
                fields.append("index")
            if "falsepositives" in new_rule:
                fields.append("falsepositives")
            if "references" in new_rule:
                fields.append("references")
            if "building_block_type" in new_rule:
                fields.append("building_block_type")
            for field in fields:
                if existing_rule[field] != new_rule[field]:
                    self.logger.info(f"Rule '{new_rule['name']}' has changed")
                    return True
        except Exception as e:
            self.logger.error(f"Error while checking rule changes {e}")
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

                params = {
                    "overwrite": "true",
                }
                headers = {
                    "kbn-xsrf": "true",
                }
                response = requests.put(
                    self._kibana_url + "/api/detection_engine/rules",
                    params=params,
                    headers=headers,
                    json=json_data,
                    verify=self._tls_verified,
                    auth=HTTPBasicAuth(self._username, self._password),
                )
            else:
                self.logger.info(
                    f"Rule '{json_data['name']}' already exists and is up to date"
                )
                return True
        else:
            headers = {
                "kbn-xsrf": "true",
            }
            response = requests.post(
                self._kibana_url + "/api/detection_engine/rules",
                headers=headers,
                json=json_data,
                verify=self._tls_verified,
                auth=HTTPBasicAuth(self._username, self._password),
            )

        if response.status_code == 200:
            return True
        else:
            raise Exception(response.text)

    def  cleanup_esql_query(self, query):
        # For the deduplication of Alerts each query needs the following fields after the FROM Statement:
        # METADATA _id, _index, _version
        # Example: FROM logs-* METADATA _id, _index, _version
        # https://www.elastic.co/guide/en/security/8.15/rules-ui-create.html#esql-non-agg-query-dedupe
        lowerquery = query.lower()
        # Ignore Correlation Rules because they already deduplicate themselves
        if "stats " in lowerquery and " by " in lowerquery:
            return query
        # Ignore if the query already contains the fields
        if "METADATA" and "_id" and "_index" and "_version" in lowerquery:
            return query
        # (^[^\|]*) - Match everything before the first pipe
        try:
            # Older Elastic Versions need brackets around the Metadata fields
            # Newer ones deprecated the brackets
            # Hence the legacy_esql flag
            if self._legacy_esql:
                query = re.sub(r"(^[^\|]*)", r"\1 [METADATA _id, _index, _version] ", query)
            else:
                query = re.sub(r"(^[^\|]*)", r"\1 METADATA _id, _index, _version ", query)
        except Exception as e:
            self.logger.error(f"Error while preparing rule for deduplication {e}")
        return query


    def create_rule(self, rule_content, rule_converted, rule_file):
        """Create an analytic rule in Elastic
        Create a scheduled alert rule in Elastic
        """

        threat = []
        tags = []
        if "tags" in rule_content and rule_content["tags"]:
            for tag in rule_content["tags"]:
                if tag.startswith("attack."):
                    parsed = self.mitre_attack_parser(tag)
                    if parsed:
                        threat += parsed
                else:
                    tags.append(tag)
        severity = rule_content["level"]
        if severity == "informational":
            severity = "low"
        risk_score = self.level_parser(severity)
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
            self.logger.error(
                f"Raw Languages need the custom parameter 'raw_language' to be set",
                extra={
                    "rule_file": rule_file,
                    "rule_converted": rule_converted,
                    "rule_content": rule_content,
                    "error": e,
                },
            )
            raise

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


        try:
            # Build the json_data for kibana import
            json_data = {
                "name": display_name,
                "enabled": enabled,
                "interval": f"{self._schedule_interval}{self._schedule_interval_unit}",
                "author": author,
                "description": rule_content["description"],
                "rule_id": rule_content["id"],
                "from": f"now-{self._schedule_interval}{self._schedule_interval_unit}",  # TODO: This should actually always be slightly more than the interval, either make it a parameter or calculate it.
                "immutable": False,
                "license": self._license,
                "output_index": "",  # TODO: Check if there should be a parameter for this
                "meta": {"from": "5m"},
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
        except Exception as e:
            print(e)


        # TODO: It might be a good idea to add more optional fields
        if "references" in rule_content:
            json_data["references"] = rule_content["references"]
        if building_block:
            json_data["building_block_type"] = "default"
        if "falsepositives" in rule_content:
            json_data["false_positives"] = rule_content["falsepositives"]

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

    def run_eql_search(self, query, es_client=None, index=None):
        response = es_client.eql.search(
            index=index,
            query=query,
            wait_for_completion_timeout=0,
            size=100,
            filter={"range": {"@timestamp": {"gte": self._eql_search_range_gte}}},
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

    def run_esql_search(self, query, es_client=None):
        response = es_client.esql.query(
            query=query,
            filter={"range": {"@timestamp": {"gte": self._esql_search_range_gte}}},
        )
        if "values" in response:
            return len(response["values"])

    def run_elastic_search(self, rule_converted, language=None, rule_content=None):

        es_client = Elasticsearch(
            self._elastic_hosts,
            basic_auth=(self._username, self._password),
            verify_certs=self._elastic_tls_verify,
            ca_certs=self._elastic_ca,
            request_timeout=300,
            max_retries=3,
        )

        index = self._index_name
        if rule_content and "custom" in rule_content and "raw_language" in rule_content["custom"]:
            language = rule_content["custom"]["raw_language"]
        print(language)
        if language == "esql":
            return self.run_esql_search(rule_converted, es_client=es_client)
        elif language == "eql":
            return self.run_eql_search(rule_converted, es_client=es_client, index=index)
        else:
            raise ValueError(f"Unsupported language: {language}")