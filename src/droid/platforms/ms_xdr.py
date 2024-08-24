"""
Module for Microsoft XDR
"""

import concurrent.futures
import re

from msgraph.core import GraphClient
from msgraph.auth import ClientSecretCredential
from msgraph.request import GraphRequest
from datetime import datetime, timedelta, timezone
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from droid.abstracts import AbstractPlatform
from droid.color import ColorLogger

logger = ColorLogger("droid.platforms.msxdr")


class MicrosoftXDRPlatform(AbstractPlatform):

    def __init__(self, parameters: dict, debug: bool, json: bool) -> None:

        super().__init__(name="Sentinel")

        self._parameters = parameters

        self._debug = debug
        self._json = json

        if "query_period" not in self._parameters:
            raise Exception(
                'MicrosoftXDRPlatform: "query_period" parameter is required.'
            )

        self.logger = ColorLogger("droid.platforms.msxdr.MicrosoftXDRPlatform")

        if self._json:
            self.logger.enable_json_logging()

        self._query_period = self._parameters["query_period"]

        self._tenant_id = self._parameters["tenant_id"]
        self._client_id = self._parameters["client_id"]
        self._client_secret = self._parameters["client_secret"]

        if "alert_prefix" in self._parameters:
            self._alert_prefix = self._parameters["alert_prefix"]

    def mssp_run_xdr_search(
        self, client, rule_converted, start_time, current_time, customer_info
    ):

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

    def run_xdr_search(self, rule_converted, rule_file, mssp_mode):

        credential = self.get_credentials()

        try:
            if self._debug:
                self.logger.debug("Creating the client instance")
            client = LogsQueryClient(credential)
            if self._debug:
                self.logger.debug("Successfully created the client instance")
        except HttpResponseError as e:
            self.logger.error(f"Error while connecting to Azure error: {e}")

        current_time = datetime.now(timezone.utc)

        start_time = current_time - timedelta(days=self._days_ago)

        try:
            if mssp_mode:
                results = {}
                client_workspaces = self.get_workspaces(credential)
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {
                        executor.submit(
                            self.mssp_run_xdr_search,
                            client,
                            rule_converted,
                            start_time,
                            current_time,
                            customer_info,
                        ): customer_info
                        for customer_info in client_workspaces
                    }

                    for future in concurrent.futures.as_completed(futures):
                        customer_info = futures[future]
                        customer, result = future.result()
                        results[customer] = result

                # Process
                total_result = 0

                for customer, result in results.items():
                    if result > 0:
                        self.logger.warning(
                            f"(Sentinel MSSP) Results for {customer}: {result}, {rule_file}"
                        )
                    else:
                        self.logger.info(
                            f"(Sentinel MSSP) No results for {customer}, {rule_file}"
                        )
                    total_result += result

                return total_result

            else:
                if self._debug:
                    self.logger.debug(f"Querying the workspace {self._workspace_id}")
                results = client.query_workspace(
                    self._workspace_id,
                    rule_converted,
                    timespan=(start_time, current_time),
                    server_timeout=self._timeout,
                )

            if results.status == LogsQueryStatus.PARTIAL:
                error = results.partial_error
                data = results.partial_data
                self.logger.error(f"Rule {rule_file} partial error in query: {error}")

            elif results.status == LogsQueryStatus.SUCCESS:

                total_result = 0

                for (
                    table
                ) in results.tables:  # results.tables contains the ... results :eyes:
                    total_result += len(table.rows)

                return total_result

        except HttpResponseError as e:
            self.logger.error(f"Rule {rule_file} error: {e}")

        except Exception as e:
            self.logger.error(f"Rule {rule_file} error: {e}")

    def get_rule(self, rule_content, rule_file):
        """Retrieve a scheduled alert rule in Sentinel
        Remove a scheduled alert rule in Sentinel
        """
        credential = self.get_credentials()

        client = SecurityInsights(credential, self._subscription_id)

        try:
            rule = client.alert_rules.get(
                resource_group_name=self._resource_group,
                workspace_name=self._workspace_name,
                rule_id=rule_content["id"],
            )
            self.logger.info(f"Successfully retrieved the rule {rule_file}")

            if rule:
                return rule
            else:
                return None

        except ResourceNotFoundError:
            self.logger.error(f"Rule not found {rule_file}")
            return None

        except Exception as e:
            self.logger.error(f"Could not retrieve the rule {rule_file}")
            raise

    def remove_rule(self, rule_content, rule_converted, rule_file):
        """Remove an analytic rule in Sentinel
        Remove a scheduled alert rule in Sentinel
        """
        credential = self.get_credentials()

        client = SecurityInsights(credential, self._subscription_id)

        try:
            client.alert_rules.delete(
                resource_group_name=self._resource_group,
                workspace_name=self._workspace_name,
                rule_id=rule_content["id"],
            )
            self.logger.info(
                f"Successfully deleted the rule {rule_file}",
                extra={
                    "rule_file": rule_file,
                    "rule_converted": rule_converted,
                    "rule_content": rule_content,
                },
            )
        except Exception as e:
            self.logger.error(
                f"Could not delete the rule {rule_file}",
                extra={
                    "rule_file": rule_file,
                    "rule_converted": rule_converted,
                    "rule_content": rule_content,
                    "error": e,
                },
            )
            raise

    def create_rule(self, rule_content, rule_converted, rule_file):
        """
        Create an Custom Detection Rule in Microsoft XDR
        """

        # Handling the display name
        if self._alert_prefix:
            display_name = self._alert_prefix + " - " + rule_content["title"]
        else:
            display_name = rule_content["title"]

        # Handling the status of the alert

        if rule_content.get("custom", {}).get("disabled") is True:
            enabled = False
            self.logger.info(f"Successfully disabled the rule {rule_file}")
        else:
            enabled = True

        # Handling the severity
        if rule_content["level"] == "critical":
            severity = "high"
        else:
            severity = rule_content["level"]

        # Handling the tactic
        if rule_content["tags"]:
            attack_tags = next(
                (
                    tag
                    for tag in rule_content.get("tags", [])
                    if tag.startswith("attack.t")
                ),
                None,
            )
            t_value = re.match(r"attack\.([tT][0-9]+)\.*.*", attack_tags)
            if t_value:
                technique_id = t_value.group(1).upper()
                tactics = None  # Temporary until sentinel allows to push technique IDs
            else:
                tactics = None
        else:
            tactics = None

        alert_rule = {
            "displayName": display_name,
            "isEnabled": enabled,
            "queryCondition": {"queryText": "DeviceProcessEvents | take 1"},
            "schedule": {"period": self._query_period},
            "detectionAction": {
                "alertTemplate": {
                    "title": display_name,
                    "description": rule_content["description"],
                    "severity": severity,
                    "category": "Execution",  # TODO: Add the correct category
                    "recommendedActions": None,  # TODO: Check if we can add recommended actions, for example the falsepositives?
                    "mitreTechniques": [],  # TODO: Check if f"tactics" works here
                    "impactedAssets": [  # TODO: Decide what all to add here
                        {
                            "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                            "identifier": "deviceId",
                        }
                    ],
                },
                "organizationalScope": None,  # TODO: Find out what this does
                "responseActions": [],  # TODO: Find out what to add here
            },
        }

        credential = ClientSecretCredential(
            self._tenant_id, self._client_id, self._client_secret
        )
        client = GraphClient(credential, base_url="https://graph.microsoft.com/beta")

        try:
            # Create the request to add the custom detection rule
            request = GraphRequest(
                client=client,
                method="POST",
                endpoint="/security/rules/detectionRules",
                json=alert_rule,
            )

            # Send the request
            response = request.send()
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
