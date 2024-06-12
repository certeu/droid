"""
Module for Azure Sentinel
"""

import concurrent.futures
import azure.mgmt.resourcegraph as arg
import re

from azure.identity import DefaultAzureCredential
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.securityinsight import SecurityInsights
from azure.mgmt.securityinsight.models import TriggerOperator
from azure.mgmt.securityinsight.models import ScheduledAlertRule
from azure.mgmt.securityinsight.models import EventGroupingSettings
from azure.mgmt.securityinsight.models import IncidentConfiguration
from azure.mgmt.securityinsight.models import GroupingConfiguration
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from datetime import datetime, timedelta, timezone
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from droid.color import ColorLogger

logger = ColorLogger("droid.platforms.sentinel")

class SentinelBase:
    """Sentinel base class

    Base class for importing datasource/product data
    """

    def __init__(self, parameters: dict) -> None:
        self.logger = ColorLogger("droid.platforms.sentinel.SentinelBase")
        self._parameters = parameters

class SentinelPlatform(SentinelBase):

    def __init__(self, parameters: dict, debug: bool, json: bool) -> None:

        super().__init__(parameters)
        self._debug = debug
        self._json = json

        if 'threshold_operator' not in self._parameters:
            raise Exception('SentinelPlatform: "threshold_operator" parameter is required.')
        if 'threshold_value' not in self._parameters:
            raise Exception('SentinelPlatform: "threshold_value" parameter is required.')
        if 'suppress_status' not in self._parameters:
            raise Exception('SentinelPlatform: "suppress_status" parameter is required.')
        if 'incident_status' not in self._parameters:
            raise Exception('SentinelPlatform: "incident_status" parameter is required.')
        if 'grouping_reopen' not in self._parameters:
            raise Exception('SentinelPlatform: "grouping_reopen" parameter is required.')
        if 'grouping_status' not in self._parameters:
            raise Exception('SentinelPlatform: "grouping_status" parameter is required.')
        if 'grouping_period' not in self._parameters:
            raise Exception('SentinelPlatform: "grouping_period" parameter is required.')
        if 'grouping_method' not in self._parameters:
            raise Exception('SentinelPlatform: "grouping_method" parameter is required.')
        if 'suppress_period' not in self._parameters:
            raise Exception('SentinelPlatform: "suppress_period" parameter is required.')
        if 'query_frequency' not in self._parameters:
            raise Exception('SentinelPlatform: "query_frequency" parameter is required.')
        if 'query_period' not in self._parameters:
            raise Exception('SentinelPlatform: "query_period" parameter is required.')
        if 'subscription_id' not in self._parameters:
            raise Exception('SentinelPlatform: "subscription_id" parameter is required.')
        if 'resource_group' not in self._parameters:
            raise Exception('SentinelPlatform: "resource_group" parameter is required.')
        if 'workspace_id' not in self._parameters:
            raise Exception('SentinelPlatform: "workspace_id" parameter is required.')
        if 'workspace_name' not in self._parameters:
            raise Exception('SentinelPlatform: "workspace_name" parameter is required.')
        if 'days_ago' not in self._parameters:
            raise Exception('SentinelPlatform: "days_ago" parameter is required.')
        if 'timeout' not in self._parameters:
            raise Exception('SentinelPlatform: "timeout" parameter is required.')

        self.logger = ColorLogger("droid.platforms.sentinel.SentinelPlatform")

        if self._json:
             self.logger.enable_json_logging()

        self._workspace_id = self._parameters["workspace_id"]
        self._workspace_name = self._parameters["workspace_name"]
        self._subscription_id = self._parameters["subscription_id"]
        self._resource_group = self._parameters["resource_group"]
        self._days_ago = self._parameters["days_ago"]
        self._threshold_operator = self._parameters["threshold_operator"]
        self._threshold_value = self._parameters["threshold_value"]
        self._query_frequency = self._parameters["query_frequency"]
        self._query_period = self._parameters["query_period"]
        self._suppress_status = self._parameters["suppress_status"]
        self._suppress_period = self._parameters["suppress_period"]
        self._incident_status = self._parameters["incident_status"]
        self._grouping_status = self._parameters["grouping_status"]
        self._grouping_reopen = self._parameters["grouping_reopen"]
        self._grouping_period = self._parameters["grouping_period"]
        self._grouping_method = self._parameters["grouping_method"]
        self._timeout = self._parameters["timeout"]

        if 'app' in (self._parameters["search_auth"] or self._parameters["export_auth"]):
            self._tenant_id = self._parameters["tenant_id"]
            self._client_id = self._parameters["client_id"]
            self._client_secret = self._parameters["client_secret"]


        if 'alert_prefix' in self._parameters:
            self._alert_prefix = self._parameters["alert_prefix"]

    def get_credentials(self):
        """Get credentials
        Authenticate on Azure using a authentication method and return the credential object
        """
        if self._parameters["search_auth"] == "default":
            if self._debug:
                self.logger.debug("Default credential selected")
            credential = DefaultAzureCredential()
        else:
            credential = ClientSecretCredential(self._tenant_id, self._client_id, self._client_secret)

        return credential

    def get_workspaces(self, credential):
        graph_query = self._parameters["graph_query"]

        subsClient = SubscriptionClient(credential)
        subsRaw = []
        for sub in subsClient.subscriptions.list():
            subsRaw.append(sub.as_dict())
        subsList = []
        for sub in subsRaw:
            subsList.append(sub.get('subscription_id'))

        argClient = arg.ResourceGraphClient(credential)
        argQueryOptions = arg.models.QueryRequestOptions(result_format="objectArray")

        argQuery = arg.models.QueryRequest(subscriptions=subsList, query=graph_query, options=argQueryOptions)

        results = argClient.resources(argQuery)

        workspace_list = []

        for entry in results.data:
            name = entry.get('name')
            workspace_id = entry.get('workspaceId')
            workspace_name = name.split('(')[1].split(')')[0]
            entry_dict = {
                "customer": workspace_name,
                "workspace_id": workspace_id
            }

            workspace_list.append(entry_dict)

        return workspace_list


    def mssp_run_sentinel_search(self,
                                 client,
                                 rule_converted,
                                 start_time,
                                 current_time,
                                 customer_info):

        customer = customer_info['customer']
        workspace_id = customer_info['workspace_id']

        results = client.query_resource(workspace_id, rule_converted, timespan=(start_time, current_time), server_timeout=self._timeout)

        result = 0

        for table in results.tables:
            result += len(table.rows)

        return customer, result

    def run_sentinel_search(self, rule_converted, rule_file, mssp_mode):

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
                    futures = {executor.submit(self.mssp_run_sentinel_search,
                                               client,
                                               rule_converted,
                                               start_time,
                                               current_time,
                                               customer_info): customer_info for customer_info in client_workspaces}

                    for future in concurrent.futures.as_completed(futures):
                        customer_info = futures[future]
                        customer, result = future.result()
                        results[customer] = result

                # Process
                total_result = 0

                for customer, result in results.items():
                    if result > 0:
                        self.logger.warning(f"(Sentinel MSSP) Results for {customer}: {result}, {rule_file}")
                    else:
                        self.logger.info(f"(Sentinel MSSP) No results for {customer}, {rule_file}")
                    total_result += result

                return total_result

            else:
                if self._debug:
                    self.logger.debug(f"Querying the workspace {self._workspace_id}")
                results = client.query_workspace(self._workspace_id,
                                                 rule_converted,
                                                 timespan=(start_time, current_time),
                                                 server_timeout=self._timeout)

            if results.status == LogsQueryStatus.PARTIAL:
                error = results.partial_error
                data = results.partial_data
                self.logger.error(f"Rule {rule_file} partial error in query: {error}")

            elif results.status == LogsQueryStatus.SUCCESS:

                total_result = 0

                for table in results.tables: # results.tables contains the ... results :eyes:
                    total_result += len(table.rows)

                return total_result

        except HttpResponseError as e:
            self.logger.error(f"Rule {rule_file} error: {e}")

        except Exception as e:
            self.logger.error(f"Rule {rule_file} error: {e}")

    def get_search(self, rule_content, rule_file):
        """Retrieve a scheduled alert rule in Sentinel
        Remove a scheduled alert rule in Sentinel
        """
        credential = self.get_credentials()

        client = SecurityInsights(credential, self._subscription_id)

        try:
            rule = client.alert_rules.get(
                resource_group_name=self._resource_group,
                workspace_name=self._workspace_name,
                rule_id=rule_content['id']
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

    def remove_search(self, rule_content, rule_converted, rule_file):
        """Remove an analytic rule in Sentinel
        Remove a scheduled alert rule in Sentinel
        """
        credential = self.get_credentials()

        client = SecurityInsights(credential, self._subscription_id)

        try:
            client.alert_rules.delete(
                resource_group_name=self._resource_group,
                workspace_name=self._workspace_name,
                rule_id=rule_content['id']
            )
            self.logger.info(f"Successfully deleted the rule {rule_file}", extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content})
        except Exception as e:
            self.logger.error(f"Could not delete the rule {rule_file}", extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content, "error": e})
            raise

    def create_search(self, rule_content, rule_converted, rule_file):
        """Create an analytic rule in Sentinel
        Create a scheduled alert rule in Sentinel
        """

        # Handling the display name
        if self._alert_prefix:
            display_name = self._alert_prefix + " " + rule_content['title']
        else:
            display_name = rule_content['title']

        # Handling the status of the alert

        if rule_content.get('custom', {}).get('disabled') is True:
            enabled = False
            self.logger.info(f"Successfully disabled the rule {rule_file}")
        else:
            enabled = True

        # Handling the severity
        if rule_content['level'] == 'critical':
            severity = 'high'
        else:
            severity = rule_content['level']

        # Handling the tactic
        if rule_content['tags']:
            attack_tags = next((tag for tag in rule_content.get('tags', []) if tag.startswith('attack.t')), None)
            t_value = re.match(r'attack\.([tT][0-9]+)\.*.*', attack_tags)
            if t_value:
                technique_id = t_value.group(1).upper()
                tactics = None # Temporary until sentinel allows to push technique IDs
            else:
                tactics = None
        else:
            tactics = None

        if self._suppress_status == True:
            suppression_enabled = True
            suppression_duration = timedelta(hours=self._suppress_period)
        else:
            suppression_enabled = False
            suppression_duration = None

        if self._incident_status == True:
            create_incident = True
            if self._grouping_status:
                grouping_config = GroupingConfiguration(
                    enabled=True,
                    reopen_closed_incident=self._grouping_reopen,
                    lookback_duration=timedelta(hours=self._grouping_period),
                    matching_method=self._grouping_method
                )
            else:
                grouping_config = None
        else:
            create_incident = False
            if self._grouping_status:
                grouping_config = GroupingConfiguration(
                    enabled=True,
                    reopen_closed_incident=self._grouping_reopen,
                    lookback_duration=timedelta(hours=self._grouping_period),
                    matching_method=self._grouping_method
                )
            else:
                grouping_config = None


        alert_rule = ScheduledAlertRule(
            #query='SecurityEvent | where EventID == "4688" and ((CommandLine contains " --adcs " and CommandLine contains " --port "))',
            query=rule_converted,
            description=rule_content['description'],
            display_name=display_name,
            severity=severity,
            query_frequency=timedelta(hours=2),
            query_period=timedelta(hours=2),
            trigger_operator=TriggerOperator(self._threshold_operator),
            trigger_threshold=self._threshold_value,
            enabled=enabled,
            suppression_duration=suppression_duration,
            suppression_enabled=suppression_enabled,
            event_grouping_settings=EventGroupingSettings(aggregation_kind="SingleAlert"),
            incident_configuration=IncidentConfiguration(create_incident=create_incident, grouping_configuration=grouping_config),
            tactics=tactics
        )

        credential = self.get_credentials()

        client = SecurityInsights(credential, self._subscription_id)

        try:
            client.alert_rules.create_or_update(
                resource_group_name=self._resource_group,
                workspace_name=self._workspace_name,
                rule_id=rule_content['id'],
                alert_rule=alert_rule
            )
            self.logger.info(f"Successfully exported the rule {rule_file}", extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content})
        except Exception as e:
            self.logger.error(f"Could not export the rule {rule_file}", extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content, "error": e})
            raise


