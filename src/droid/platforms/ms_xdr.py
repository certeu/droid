"""
Module for Microsoft XDR
"""

import concurrent.futures
import re
from pprint import pprint
import asyncio
import msal
import requests
import json
import time
from datetime import datetime, timedelta, timezone
from droid.abstracts import AbstractPlatform
from droid.color import ColorLogger


logger = ColorLogger("droid.platforms.msxdr")


class MicrosoftXDRPlatform(AbstractPlatform):

    def __init__(self, parameters: dict, debug: bool, json: bool) -> None:

        super().__init__(name="Microsoft XDR")

        self._parameters = parameters

        self._debug = debug
        self._json = json

        if "query_period" not in self._parameters:
            raise Exception(
                'MicrosoftXDRPlatform: "query_period" parameter is required.'
            )
        elif self._parameters["query_period"].upper() not in [
            "0",
            "1H",
            "3H",
            "12H",
            "24H",
        ]:
            raise Exception(
                'MicrosoftXDRPlatform: "query_period" parameter must be one of "0", "1H", "3H", "12H" or "24H".'
            )

        self.logger = ColorLogger("droid.platforms.msxdr.MicrosoftXDRPlatform")

        if self._json:
            self.logger.enable_json_logging()

        self._query_period = self._parameters["query_period"]

        self._tenant_id = self._parameters["tenant_id"]
        self._client_id = self._parameters["client_id"]
        self._client_secret = self._parameters["client_secret"]
        self._api_base_url = "https://graph.microsoft.com/beta"
        self._token = self.acquire_token()
        self._headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        if "alert_prefix" in self._parameters:
            self._alert_prefix = self._parameters["alert_prefix"]
        else:
            self._alert_prefix = None

    def mssp_run_xdr_search(
        self, client, rule_converted, start_time, current_time, customer_info
    ):
        # TODO: Provide a list of tenant ids and process
        return None

        customer = customer_info["customer"]
        workspace_id = customer_info["workspace_id"]

        results = client.query_resource(
            workspace_id,
            rule_converted,
            timespan=(start_time, current_time),
            server_timeout=self._timeout,
        )

        result = 0

        for table in results.tables:
            result += len(table.rows)

        return customer, result

    def run_xdr_search(self, rule_converted, rule_file):
        payload = {"Query": rule_converted, "Timespan": "P1D"}
        try:
            results, status_code = self._post(
                url="/security/runHuntingQuery", payload=payload
            )
            if "error" in results:
                self.logger.error(
                    f"Error while running the query {results['error']['message']}"
                )
                raise
            else:
                return len(results["results"])
        except Exception as e:
            self.logger.error(f"Error while running the query {e}")
            raise

    def get_rule(self, rule_id):
        """Retrieve a scheduled alert rule in Microsoft XDR
        Remove a scheduled alert rule in Microsoft XDR
        """
        try:
            params = {"$filter": f"contains(displayName, '{rule_id}')"}
            rule, status_code = self._get(
                url="/security/rules/detectionRules", params=params
            )
            if len(rule["value"]) > 0:
                return rule["value"][0]
            else:
                return None
        except Exception as e:
            self.logger.error(f"Error while searching for rule id {rule_id}")
            raise

    def remove_rule(self, rule_content, rule_converted, rule_file):
        """
        Remove a Custom Detection Rule in Microsoft XDR
        """
        existing_rule = self.get_rule(rule_content["id"])
        if existing_rule:

            api_url = f"{self._api_base_url}/security/rules/detectionRules/{existing_rule['id']}"
            response = requests.delete(api_url, headers=self._headers)

            if response.status_code == 204:
                self.logger.info(
                    f"Rule {rule_file} was successfully deleted",
                    extra={
                        "rule_file": rule_file,
                        "rule_converted": rule_converted,
                        "rule_content": rule_content})
            else:
                self.logger.error(
                    f"Could not deleted {rule_file} - error: {response.json()['error']['message']}",
                    extra={
                        "rule_file": rule_file,
                        "rule_converted": rule_converted,
                        "rule_content": rule_content
                    })
                raise

    def acquire_token(self):
        # MSAL configuration
        authority = f"https://login.microsoftonline.com/{self._tenant_id}"
        scope = ["https://graph.microsoft.com/.default"]

        # Create a confidential client application
        app = msal.ConfidentialClientApplication(
            self._client_id, authority=authority, client_credential=self._client_secret
        )

        # Acquire a token
        result = app.acquire_token_for_client(scopes=scope)

        if "access_token" in result:
            token = result["access_token"]
            return token
        else:
            self.logger.error(f'Failed to acquire token: {result["error_description"]}')
            exit()

    def create_rule(self, rule_content, rule_converted, rule_file):
        """
        Create an Custom Detection Rule in Microsoft XDR
        """

        # Handling the display name
        display_name = rule_content["title"] + " - " + rule_content["id"]
        if self._alert_prefix:
            display_name = self._alert_prefix + " - " + display_name

        # Handling the alert title

        alert_title = rule_content["title"]
        if self._alert_prefix:
            alert_title = self._alert_prefix + " - " + alert_title

        # Handling the status of the alert

        if rule_content.get("custom", {}).get("disabled") is True:
            enabled = False
            self.logger.info(f"Disabling the rule {rule_file}")
        else:
            enabled = True

        # Handling the severity
        if rule_content["level"] == "critical":
            severity = "high"
        else:
            severity = rule_content["level"]
        mitreTechniques = []
        category = None
        if "tags" in rule_content:
            for tag in rule_content["tags"]:
                if tag.lower().startswith("attack."):
                    t_value = re.match(r"attack\.([tT][0-9]{4}(\.[0-9]{3})?)", tag)
                    if t_value:
                        technique = t_value.group(1).upper()
                        mitreTechniques.append(technique)
                    c_value = tag.replace("attack.", "").lower().strip()
                    if c_value in [
                        "reconnaissance",
                        "resource_development",
                        "initial_access",
                        "execution",
                        "persistence",
                        "privilege_escalation",
                        "defense_evasion",
                        "credential_access",
                        "discovery",
                        "lateral_movement",
                        "collection",
                        "command_and_control",
                        "exfiltration",
                        "impact",
                    ]:
                        category = c_value.replace("_", " ").title().replace(" ", "")
        if not category:
            category = "Execution"  # Fallback... this should never happen
        try:
            alert_rule = {
                "displayName": display_name,
                "isEnabled": enabled,
                "queryCondition": {"queryText": rule_converted},
                "schedule": {"period": self._query_period.upper()},
                "detectionAction": {
                    "alertTemplate": {
                        "title": alert_title,
                        "description": rule_content["description"],
                        "severity": severity,
                        "category": category,
                        "recommendedActions": None,  # TODO: Check if we can add recommended actions, for example the falsepositives?
                        "mitreTechniques": mitreTechniques,
                        "impactedAssets": [  # This is default, it can be overwritten by the custom rule fields
                            {
                                "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                                "identifier": "deviceId",
                            },
                        ],
                    },
                    "organizationalScope": None,  # TODO: Find out what this does
                    "responseActions": [],  # TODO: Define Actions in custom rule fields
                },
            }
        except Exception as e:
            self.logger.error(e)

        if "custom" in rule_content:
            if "query_period" in rule_content["custom"]:
                query_period = rule_content["custom"]["query_period"].upper()
                if query_period in [
                    "0",
                    "1H",
                    "3H",
                    "12H",
                    "24H",
                ]:
                    alert_rule["schedule"]["period"] = query_period
                else:
                    self.logger.error(
                        f"Sigma Query Period must be one of '0', '1H', '3H', '12H' or '24H', used value provided in the config {self._query_period} - {rule_file}"
                    )
            if "actions" in rule_content["custom"]:
                responseActions = self.parse_actions(
                    rule_content["custom"]["actions"], rule_file=rule_file
                )
                alert_rule["detectionAction"]["responseActions"] = responseActions
            if "impactedAssets" in rule_content["custom"]:
                impactedAssets = self.parse_impactedAssets(
                    rule_content["custom"]["impactedAssets"], rule_file=rule_file
                )
                alert_rule["detectionAction"]["alertTemplate"][
                    "impactedAssets"
                ] = impactedAssets
        try:
            self.push_detection_rule(
                alert_rule=alert_rule,
                rule_content=rule_content,
                rule_file=rule_file,
                rule_converted=rule_converted,
            )
            # Send the JSON payload to Microsoft Graph Security API

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

    def check_rule_changes(self, existing_rule, new_rule):
        try:
            change = False
            global_fields = [
                "displayName",
                "isEnabled",
            ]
            alertTemplate_fields = [
                "title",
                "description",
                "severity",
                "category",
                "recommendedActions",
                "mitreTechniques",
                "impactedAssets",
            ]

            for field in global_fields:
                if existing_rule[field] != new_rule[field]:
                    change = True
            for field in alertTemplate_fields:
                if (
                    existing_rule["detectionAction"]["alertTemplate"][field]
                    != new_rule["detectionAction"]["alertTemplate"][field]
                ):
                    change = True
            if (
                existing_rule["queryCondition"]["queryText"]
                != new_rule["queryCondition"]["queryText"]
            ):
                change = True
            if existing_rule["schedule"]["period"] != new_rule["schedule"]["period"]:
                change = True
            if (
                existing_rule["detectionAction"]["responseActions"]
                != new_rule["detectionAction"]["responseActions"]
            ):
                change = True
        except Exception as e:
            self.logger.error(f"Error while checking rule changes {e}")
            return True
        if change:
            self.logger.info(f"Rule '{new_rule['displayName']}' has changed")
            return True
        else:
            self.logger.info(
                f"Rule '{new_rule['displayName']}' already exists and is up to date"
            )
            return False

    def push_detection_rule(
        self, alert_rule=None, rule_content=None, rule_file=None, rule_converted=None
    ):
        existing_rule = self.get_rule(rule_content["id"])
        if existing_rule:
            self.logger.info("Rule already exists")
            if not self.check_rule_changes(existing_rule, alert_rule):
                return True
            else:
                api_url = f"/security/rules/detectionRules/{existing_rule['id']}"
                response, status_code = self._patch(url=api_url, payload=alert_rule)
        else:
            api_url = "/security/rules/detectionRules"
            response, status_code = self._post(url=api_url, payload=alert_rule)

        if status_code == 400:
            self.logger.error(
                f"Could not export the rule {rule_file} due to a bad request. {response['error']['message']}",
                extra={
                    "rule_file": rule_file,
                    "rule_converted": rule_converted,
                    "rule_content": rule_content,
                    "error": response,
                },
            )
        elif status_code == 403:
            self.logger.error(
                f"Could not export the rule {rule_file} due to insufficient permissions. {response}",
                extra={
                    "rule_file": rule_file,
                    "rule_converted": rule_converted,
                    "rule_content": rule_content,
                    "error": response,
                },
            )
        elif status_code == 201 or 200:
            if "error" in response:
                self.logger.error(
                    f"Could not export the rule {rule_file}",
                    extra={
                        "rule_file": rule_file,
                        "rule_converted": rule_converted,
                        "rule_content": rule_content,
                        "error": response,
                    },
                )
                raise Exception(response)
            else:
                self.logger.info(
                    f"Successfully exported the rule {rule_file}",
                    extra={
                        "rule_file": rule_file,
                        "rule_converted": rule_converted,
                        "rule_content": rule_content,
                    },
                )
        else:
            print(status_code)
            pprint(response)

    def parse_actions(self, actions, rule_file=None):
        # This whole function is a mess
        # It might be better to have a schema validation for the actions
        response_actions = []
        for action in actions:
            response_action = {}
            if "action" in action:
                action_name = action["action"]
                if not action_name in [
                    "forceUserPasswordReset",
                    "disableUser",
                    "markUserAsCompromised",
                    "stopAndQuarantineFile",
                    "restrictAppExecution",
                    "initiateInvestigation",
                    "runAntivirusScan",
                    "collectInvestigationPackage",
                    "isolateDevice",
                    "blockFile",
                    "allowFile",
                ]:
                    self.logger.warning(
                        f"Only these actiontypes are allowed: forceUserPasswordReset, disableUser, markUserAsCompromised, stopAndQuarantineFile, restrictAppExecution, initiateInvestigation, runAntivirusScan, collectInvestigationPackage, isolateDevice, blockFile, allowFile. {rule_file}"
                    )
                    continue
                response_action["@odata.type"] = (
                    f"#microsoft.graph.security.{action_name}ResponseAction"
                )
                # Isolate Device needs the field isolationType
                if action_name == "isolateDeviceResponseAction":
                    if "isolationType" in action:
                        response_action["isolationType"] = action["isolationType"]
                    else:
                        self.logger.error(
                            f"Isolation Type ('selective' or 'full') is missing from the rule {rule_file}"
                        )
                        raise
                # Block File needs the field deviceGroupNames but it can easily be an empty list
                if action_name == "blockFileResponseAction":
                    if "deviceGroupNames" in action:
                        if isinstance(action["deviceGroupNames"], str):
                            response_action["deviceGroupNames"] = [
                                action["deviceGroupNames"]
                            ]
                        elif isinstance(action["deviceGroupNames"], list):
                            response_action["deviceGroupNames"] = action[
                                "deviceGroupNames"
                            ]
                        elif action["deviceGroupNames"] is None:
                            response_action["deviceGroupNames"] = []
                        else:
                            response_action["deviceGroupNames"] = []
                # These actions all have an identifier invisible in the GUI.
                # So we add it automatically, it's still possible to overwrite though
                if action_name in [
                    "restrictAppExecution",
                    "initiateInvestigation",
                    "runAntivirusScan",
                    "collectInvestigationPackage",
                    "isolateDevice",
                ]:
                    response_action["identifier"] = "deviceId"
            else:
                self.logger.error(f"Action Name is missing from the rule {rule_file}")
                raise
            if "identifier" in action:
                if isinstance(action["identifier"], list):
                    identifier = ",".join(action["identifier"])
                else:
                    identifier = action["identifier"]
                # Define a mapping of action names to valid identifiers
                valid_identifiers = {
                    "forceUserPasswordReset": [
                        "accountSid",
                        "initiatingProcessAccountSid",
                    ],
                    "initiatingProcessAccountSid": [
                        "accountSid",
                        "initiatingProcessAccountSid",
                    ],
                    "markUserAsCompromised": [
                        "accountObjectId",
                        "initiatingProcessAccountObjectId",
                    ],
                    "stopAndQuarantineFile": ["sha1", "initiatingProcessSHA1"],
                    "blockFile": [
                        "sha256",
                        "sha1",
                        "initiatingProcessSHA1",
                        "initiatingProcessSHA256",
                    ],
                    "allowFile": [
                        "sha256",
                        "sha1",
                        "initiatingProcessSHA1",
                        "initiatingProcessSHA256",
                    ],
                }
                # Check if the action_name is in the valid_identifiers dictionary
                if action_name in valid_identifiers:
                    if identifier not in valid_identifiers[action_name]:
                        self.logger.error(
                            f"Identifier for {action_name} must be one of {valid_identifiers[action_name]} - {rule_file}"
                        )
                        raise
                # And of course there is an exeption
                # stopAndQuarantineFile needs deviceId as always, but in a comma separated list... MS Graph API is weird
                if action_name == "stopAndQuarantineFile":
                    identifier += ",deviceId"
                response_action["identifier"] = identifier
            if not "identifier" in response_action:
                self.logger.error(
                    f"Action Identifier is missing from the rule {rule_file}"
                )
                raise

            response_actions.append(response_action)
        return response_actions

    def parse_impactedAssets(self, impactedAssets, rule_file=None):
        impactedAssetsList = []
        for asset in impactedAssets:
            if "impactedAssetType" in asset and "identifier" in asset:
                impactedAssetType = asset["impactedAssetType"].capitalize()
                identifier = asset["identifier"]
                # Define a mapping of action names to valid identifiers
                valid_identifiers = {
                    "Device": ["deviceId", "deviceName"],
                    "Mailbox": ["accountUpn", "initiatingProcessAccountUpn"],
                    "User": [
                        "accountObjectId",
                        "accountSid",
                        "accountUpn",
                        "initiatingProcessAccountObjectId",
                        "initiatingProcessAccountSid",
                        "initiatingProcessAccountUpn",
                        "targetAccountUpn",
                    ],
                }
                # Check if the action_name is in the valid_identifiers dictionary
                if impactedAssetType in valid_identifiers:
                    if identifier not in valid_identifiers[impactedAssetType]:
                        self.logger.error(
                            f"Identifier for {impactedAssetType} must be one of {valid_identifiers[impactedAssetType]} - {rule_file}"
                        )
                        raise
                    else:
                        impactedAsset = {
                            "@odata.type": f"#microsoft.graph.security.impacted{impactedAssetType}Asset",
                            "identifier": identifier,
                        }
                        impactedAssetsList.append(impactedAsset)
                else:
                    self.logger.error(
                        f"Impacted Asset Type {impactedAssetType} is not valid - {rule_file}"
                    )
                    raise
        return impactedAssetsList

    def _get(self, url=None, headers=None, params=None):
        # Send the JSON payload to Microsoft Graph Security API
        api_url = self._api_base_url + url
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        if headers:
            headers.update(headers)
        while True:
            response = requests.get(api_url, headers=headers, params=params)
            if response.status_code == 429:
                self.logger.debug("Rate limit reached, waiting 60 seconds")
                time.sleep(60)
            else:
                break

        return response.json(), response.status_code

    def _post(self, url=None, payload=None, headers=None, params=None):
        # Send the JSON payload to Microsoft Graph Security API
        api_url = self._api_base_url + url
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        if headers:
            headers.update(headers)
        while True:
            response = requests.post(api_url, headers=headers, json=payload)
            if response.status_code == 429:
                self.logger.debug("Rate limit reached, waiting 60 seconds")
                time.sleep(60)
            else:
                break
        return response.json(), response.status_code

    def _patch(self, url=None, payload=None, headers=None, params=None):
        # Send the JSON payload to Microsoft Graph Security API
        api_url = self._api_base_url + url
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        if headers:
            headers.update(headers)
        while True:
            response = requests.patch(api_url, headers=headers, json=payload)
            if response.status_code == 429:
                logger.debug("Rate limit reached, waiting 60 seconds")
                time.sleep(60)
            else:
                break
        return response.json(), response.status_code
