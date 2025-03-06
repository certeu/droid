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
from azure.mgmt.securityinsight.models import EntityMapping, FieldMapping
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from datetime import datetime, timedelta, timezone
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from droid.abstracts import AbstractPlatform
from droid.color import ColorLogger

class SentinelPlatform(AbstractPlatform):

    def __init__(self, parameters: dict, logger_param: dict, export_mssp: bool=False) -> None:

        super().__init__(name="Sentinel")

        self._parameters = parameters
        self._export_mssp = export_mssp

        self.logger = ColorLogger(__name__, **logger_param)

        required_parameters = [
            "threshold_operator",
            "threshold_value",
            "suppress_status",
            "incident_status",
            "grouping_reopen",
            "grouping_status",
            "grouping_period",
            "grouping_method",
            "suppress_period",
            "query_frequency",
            "query_period",
            "subscription_id",
            "resource_group",
            "workspace_id",
            "workspace_name",
            "days_ago",
            "timeout"
        ]

        for param in required_parameters:
            if param not in self._parameters:
                raise Exception(f'SentinelPlatform: "{param}" parameter is required.')

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

        # Optional fields

        self._alert_prefix = self._parameters.get("alert_prefix", None)
        self._export_list_mssp = self._parameters.get("export_list_mssp", None)
        self._mssp_search_exclude_list = self._parameters.get("mssp_search_exclude_list", None)

    def mitre_tactics(self, rule_content) -> list:
        """
        Extracts and returns a list of MITRE ATT&CK tactics from the provided rule content.

        Returns:
            A list of of MITRE ATT&CK tactics or None
        """
        tactic_mapping = {
            "reconnaissance": "Reconnaissance",
            "resource-development": "ResourceDevelopment",
            "initial-access": "InitialAccess",
            "execution": "Execution",
            "persistence": "Persistence",
            "privilege-escalation": "PrivilegeEscalation",
            "defense-evasion": "DefenseEvasion",
            "credential-access": "CredentialAccess",
            "discovery": "Discovery",
            "lateral-movement": "LateralMovement",
            "collection": "Collection",
            "command-and-control": "CommandAndControl",
            "exfiltration": "Exfiltration",
            "impact": "Impact",
            "pre-attack": "PreAttack",
            "impair-process-control": "ImpairProcessControl",
            "inhibit-response-function": "InhibitResponseFunction",
        }

        tactics_found = []

        for tag in rule_content.get("tags", []):
            tactic = tag.replace("attack.", "").lower().strip()
            if tactic in tactic_mapping:
                tactics_found.append(tactic_mapping[tactic])

        return tactics_found or None


    def mitre_techniques(self, rule_content) -> list:
        """
        Extracts and returns a list of unique MITRE ATT&CK techniques (excluding sub-techniques) from the provided rule content.

        Returns:
            A list of of MITRE ATT&CK techniques or None
        """
        attack_regex = re.compile(r"attack\.([tT][0-9]{4})(\.[0-9]{3})?")

        mitre_techniques = {
            attack_regex.match(tag).group(1).upper()
            for tag in rule_content.get("tags", [])
            if tag.lower().startswith("attack.") and attack_regex.match(tag)
        }

        return list(mitre_techniques) if mitre_techniques else None

    def get_credentials(self):
        """Get credentials
        Authenticate on Azure using a authentication method and return the credential object
        """
        if self._parameters["search_auth"] == "default":
            self.logger.debug("Default credential selected")
            credential = DefaultAzureCredential()
        else:
            credential = ClientSecretCredential(self._tenant_id, self._client_id, self._client_secret)

        return credential

    def get_workspaces(self, credential, export_mode=False):

        if export_mode:
            graph_query = 'resources | where name contains "SecurityInsights" | extend workspaceId = tostring(properties.workspaceResourceId) | project name, resourceGroup, subscriptionId'
            graph_key = "resourceGroup"
        else:
            graph_query = 'resources | where name contains "SecurityInsights" | extend workspaceId = tostring(properties.workspaceResourceId) | project name, workspaceId'
            graph_key = "workspaceId"

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
            graph_value = entry.get(graph_key)
            workspace_name = name.split('(')[1].split(')')[0]
            if export_mode:
                entry_dict = {
                    "customer": workspace_name,
                    graph_key: graph_value,
                    "subscription_id": entry.get("subscriptionId")
                }
            else:
                entry_dict = {
                    "customer": workspace_name,
                    "workspace_id": graph_value
                }

            workspace_list.append(entry_dict)

        workspace_list = [entry for entry in workspace_list if entry["customer"] not in self._export_list_mssp]

        return workspace_list

    def get_export_list_mssp(self) -> list:

        if self._export_list_mssp:
            self.logger.info("Integrity check for designated customers")
            return self._export_list_mssp
        else:
            self.logger.error("No export_list_mssp found")
            raise

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

    def mssp_run_sentinel_export(
            self, client, rule_content,
            rule_converted, customer_info, alert_rule
            ) -> None:
        customer = customer_info['customer']
        resource_group_name = customer_info['resourceGroup']

        try:
            client.alert_rules.create_or_update(
                        resource_group_name=resource_group_name,
                        workspace_name=customer,
                        rule_id=rule_content['id'],
                        alert_rule=alert_rule
            )
        except Exception as e:
            self.logger.error(f"(MSSP) Could not export the rule. Error: {e}", extra={
                "rule_converted": rule_converted,
                "customer": customer,
                "resource_group_name": resource_group_name,
                "rule_content": rule_content,
                "error": e
            })
            raise

    def run_sentinel_search(self, rule_converted, rule_file, mssp_mode):

        credential = self.get_credentials()

        try:
            self.logger.debug("Creating the client instance")
            client = LogsQueryClient(credential)
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

                for table in results.tables:
                    total_result += len(table.rows)

                return total_result

        except HttpResponseError as e:
            self.logger.error(f"Rule {rule_file} error: {e}")

        except Exception as e:
            self.logger.error(f"Rule {rule_file} error: {e}")

    def get_rule_mssp(self, rule_content, rule_file,
                      tenant_id, subscription_id, resource_group_name,
                      workspace_name):
        """Retrieve a scheduled alert rule in Sentinel in MSSP mode
        """

        self._tenant_id = tenant_id
        credential = self.get_credentials()

        client = SecurityInsights(credential, subscription_id)

        try:
            rule = client.alert_rules.get(
                resource_group_name=resource_group_name,
                workspace_name=workspace_name,
                rule_id=rule_content['id']
            )
            self.logger.info(f"Successfully retrieved the rule {rule_file} for {workspace_name}")

            if rule:
                return rule
            else:
                return None

        except ResourceNotFoundError:
            return None

        except Exception as e:
            self.logger.error(f"Could not retrieve the rule {rule_file} in {workspace_name}")
            raise

    def get_rule(self, rule_content, rule_file):
        """Retrieve a scheduled alert rule in Sentinel
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
            return None

        except Exception as e:
            self.logger.error(f"Could not retrieve the rule {rule_file}")
            raise

    def remove_rule(self, rule_content, rule_converted, rule_file):
        """Remove an analytic rule in Sentinel
        Remove a scheduled alert rule in Sentinel
        """
        if self._export_mssp:
            if self._export_list_mssp:
                error = False
                self.logger.info("Exporting deletion to designated customers")
                for group, info in self._export_list_mssp.items():
                    workspace_name = info['workspace_name']
                    self._tenant_id = info['tenant_id']
                    resource_group_name = info['resource_group_name']
                    subscription_id = info['subscription_id']

                    self.logger.debug(f"Exporting deletion to {workspace_name} from group id {group}")

                    credential = self.get_credentials()

                    client = SecurityInsights(credential, subscription_id)

                    try:
                        client.alert_rules.delete(
                            resource_group_name=resource_group_name,
                            workspace_name=workspace_name,
                            rule_id=rule_content['id']
                        )
                        self.logger.info(f"Successfully deleted the rule {rule_file} from {workspace_name}")
                    except Exception as e:
                        self.logger.error(f"Failed to delete the rule {rule_file} from {workspace_name} - error: {e}")
                        error = True
                if error:
                    raise
            else:
                self.logger.error("Export list not found. Please provide the list of designated customers")
                raise
        else:
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


    def create_rule(self, rule_content, rule_converted, rule_file):
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

        # Handling the entities
        if rule_content.get('custom', {}).get('entity_mappings'):
            entity_mappings = []
            for mapping in rule_content['custom']['entity_mappings']:
                field_mappings = [FieldMapping(identifier=field['identifier'], column_name=field['column_name'])
                                    for field in mapping['field_mappings']]
                entity_mappings.append(EntityMapping(entity_type=mapping['entity_type'], field_mappings=field_mappings))
        else:
            entity_mappings = None

        # Handling the severity
        if rule_content['level'] == 'critical':
            severity = 'high'
        else:
            severity = rule_content['level']

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
            query=rule_converted,
            description=rule_content['description'],
            display_name=display_name,
            severity=severity,
            query_frequency=timedelta(hours=self._query_frequency),
            query_period=timedelta(hours=self._query_period),
            trigger_operator=TriggerOperator(self._threshold_operator),
            trigger_threshold=self._threshold_value,
            enabled=enabled,
            suppression_duration=suppression_duration,
            suppression_enabled=suppression_enabled,
            event_grouping_settings=EventGroupingSettings(aggregation_kind="SingleAlert"),
            incident_configuration=IncidentConfiguration(create_incident=create_incident, grouping_configuration=grouping_config),
            tactics=self.mitre_tactics(rule_content),
            entity_mappings=entity_mappings,
            techniques=self.mitre_techniques(rule_content)
        )

        if rule_content.get("custom", {}).get("query_frequency"):
            alert_rule.query_frequency = timedelta(hours=rule_content["custom"]["query_frequency"])

        if rule_content.get("custom", {}).get("query_period"):
            alert_rule.query_period = timedelta(hours=rule_content["custom"]["query_period"])

        if self._export_mssp:
            if self._export_list_mssp:
                error = False
                self.logger.info("Exporting to designated customers")
                for group, info in self._export_list_mssp.items():

                    workspace_name = info['workspace_name']
                    self._tenant_id = info['tenant_id']
                    resource_group_name = info['resource_group_name']
                    subscription_id = info['subscription_id']

                    self.logger.debug(f"Exporting to {workspace_name} from group id {group}")

                    credential = self.get_credentials()

                    # Create a new SecurityInsights client for the target subscription
                    client = SecurityInsights(credential, subscription_id)

                    try:
                        client.alert_rules.create_or_update(
                            resource_group_name=resource_group_name,
                            workspace_name=workspace_name,
                            rule_id=rule_content['id'],
                            alert_rule=alert_rule
                        )
                        self.logger.info(f"Successfully exported the rule {rule_file} to {workspace_name}")
                    except Exception as e:
                        self.logger.error(f"Failed to export the rule {rule_file} to {workspace_name} - error: {e}")
                        error = True
                if error:
                    raise
            else:
                self.logger.error("Export list not found. Please provide the list of designated customers")
                raise
        else:
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
                self.logger.error(f"Could not export the rule {rule_file} - error: {e}", extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content, "error": e})
                raise

