"""
Module for Elastic Security
"""

from droid.color import ColorLogger
import io
import json
from pprint import pprint
import requests
from requests.auth import HTTPBasicAuth
from sigma.data.mitre_attack import (
    mitre_attack_techniques,
    mitre_attack_techniques_tactics_mapping,
    mitre_attack_tactics,
)
import os

logger = ColorLogger("droid.platforms.elastic")


class ElasticBase:
    """Elastic base class

    Base class for importing datasource/product data
    """

    def __init__(self, parameters: dict) -> None:
        self.logger = ColorLogger("droid.platforms.elastic.ElasticBase")
        self._parameters = parameters


class ElasticPlatform(ElasticBase):

    def __init__(
        self, parameters: dict, debug: bool, json: bool, language: str
    ) -> None:

        super().__init__(parameters)
        self._debug = debug
        self._json = json

        if "kibana_url" not in self._parameters:
            raise ValueError("ElasticPlatform: 'kibana_url' is not set.")

        if "kibana_ca" not in self._parameters:
            self._parameters["kibana_ca"] = False
        if "tls_verify" not in self._parameters:
            self._parameters["tls_verify"] = True

        if "schedule_interval" not in self._parameters:
            logger.debug(
                "ElasticPlatform: 'schedule_interval' is not set, using default of 1."
            )
            self._parameters["schedule_interval"] = "1"

        if "schedule_interval_unit" not in self._parameters:
            logger.debug(
                "ElasticPlatform: 'schedule_interval_unit' is not set, using default of h."
            )
            self._parameters["schedule_interval_unit"] = "h"

        if "license" not in self._parameters:
            logger.debug("ElasticPlatform: 'license' is not set, using default of DRL.")
            self._parameters["license"] = "DRL"

        self.logger = ColorLogger("droid.platforms.elastic.ElasticPlatform")

        if self._json:
            self.logger.enable_json_logging()

        self._schedule_interval = self._parameters["schedule_interval"]
        self._schedule_interval_unit = self._parameters["schedule_interval_unit"]
        self._license = self._parameters["license"]
        self._kibana_url = self._parameters["kibana_url"]
        self._kibana_ca = self._parameters["kibana_ca"]
        self._tls_verify = self._parameters["tls_verify"]
        self._language = language

        if self._parameters["auth_method"] == "basic":
            self._username = self._parameters["username"]
            self._password = self._parameters["password"]

        if "alert_prefix" in self._parameters:
            self._alert_prefix = self._parameters["alert_prefix"]
        else:
            self._alert_prefix = None

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

    def remove_search(self, rule_content, rule_converted, rule_file):
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

    def kibana_import_rule(self, json_data):
        existing_rule = self.get_rule(json_data["rule_id"])
        if existing_rule:
            if existing_rule["language"] != json_data["language"]:
                self.logger.error(
                    f"Rule '{json_data['name']}' already exists with a different language. Delete the existing rule or change the language of the rule"
                )
                return
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

    def index_parser(self, logsource):
        if "product" in logsource:
            logsource = logsource["product"]
        else:
            self.logger.error("No Product Specified in Logsource")
            return None
        if logsource.lower() == "windows":
            return ["logs-system.*", "logs-windows.*"]
        else:
            self.logger.error("No known index for Logsource")
            return ["logs-*"]

    def create_search(self, rule_content, rule_converted, rule_file):
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
            self.logger.info(f"Successfully building_block the rule {rule_file}")
        else:
            building_block = False

        # Handling the display name
        if self._alert_prefix:
            display_name = self._alert_prefix + " - " + rule_content["title"]
        else:
            display_name = rule_content["title"]
        if building_block:
            display_name = "BB - " + display_name
        # Handling the status of the alert

        if rule_content.get("custom", {}).get("disabled") is True:
            enabled = False
            self.logger.info(f"Successfully disabled the rule {rule_file}")
        else:
            enabled = True

        language = self._language
        if "custom" in rule_content and "raw_language" in rule_content["custom"]:
            language = rule_content["custom"]["raw_language"]

        if language == "esql":
            index = None
        else:
            # TODO: There needs to be a discussion about how to handle this
            # Hardcoding Indexes is not a good idea
            # Could maybe use a custom field in the rule to specify the index?
            # index = self.index_parser(rule_content["logsource"])
            index = ["logs-*"]  # Hardcoded to logs-* for now

        # Build the json_data for kibana import
        json_data = {
            # "id": rule_content["id"],
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
            "index": index,
            "query": rule_converted,
            "filters": [],
            "actions": [],
        }
        # TODO: It might be a good idea to add more optional fields
        if "references" in rule_content:
            json_data["references"] = rule_content["references"]
        if "elastic.bb" in tags:
            json_data["building_block_type"] = "default"
        if "falsepositives" in rule_content:
            json_data["false_positives"] = rule_content["falsepositives"]

        try:
            self.kibana_import_rule(json_data)
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
