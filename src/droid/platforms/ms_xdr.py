"""
Module for Microsoft XDR
"""

import re
import requests
import time
import yaml

from os import environ
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta, timezone
from droid.abstracts import AbstractPlatform
from droid.color import ColorLogger
from droid.platforms.common import get_error_message, get_pipeline_group_match, get_search_days_ago, get_token_hook_headers
from droid.variants import customer_serves_variant
from msal import ConfidentialClientApplication
from azure.identity import DefaultAzureCredential
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.backends import default_backend
from typing import Optional, Callable

# Sanity bound on a single Retry-After delay. Graph quota windows are minutes, not
# hours, so anything above this is a malformed header rather than a real wait.
MAX_RETRY_AFTER_SECONDS = 3600

# Graph times a single hunting query out after three minutes, and a heavy tenant
# really does take that long. The client waits slightly past the server limit so
# the timeout comes back as an error explaining itself, rather than as an aborted
# connection the retry loop then runs four more times.
# https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview
HUNTING_QUERY_TIMEOUT = 190

# Total time a single request may spend waiting on throttling before giving up.
# Tenant quota windows run to ~35 minutes, so the budget has to clear one of them
# for a run to survive it. Overridable with the "max_throttle_wait" parameter.
DEFAULT_MAX_THROTTLE_WAIT = 3600

# Budget headers Graph may attach to a throttled response, reported under --debug
# to explain which limit was hit (https://learn.microsoft.com/en-us/graph/throttling)
THROTTLING_HEADERS = (
    "Retry-After",
    "RateLimit-Limit",
    "RateLimit-Remaining",
    "RateLimit-Reset",
    "x-ms-resource-unit",
)

# Sigma attack.<tactic> tags, and the MITRE tactic names Graph expects
MITRE_TACTICS = {
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
}

# custom.actions action names, the automatedActions collection each one fills,
# and the identifiers it accepts
AUTOMATED_ACTIONS = {
    "forceUserPasswordReset": ("forceUserPasswordResets", ["accountSid", "initiatingProcessAccountSid"]),
    "disableUser": ("disableUsers", ["accountSid", "initiatingProcessAccountSid"]),
    "markUserAsCompromised": ("markUsersAsCompromised", ["accountObjectId", "initiatingProcessAccountObjectId"]),
    "stopAndQuarantineFile": ("stopAndQuarantineFiles", ["sha1", "initiatingProcessSHA1"]),
    "blockFile": ("blockFiles", ["sha256", "sha1", "initiatingProcessSHA1", "initiatingProcessSHA256"]),
    "allowFile": ("allowFiles", ["sha256", "sha1", "initiatingProcessSHA1", "initiatingProcessSHA256"]),
    "restrictAppExecution": ("restrictAppExecutions", ["deviceId"]),
    "initiateInvestigation": ("initiateInvestigations", ["deviceId"]),
    "runAntivirusScan": ("runAntivirusScans", ["deviceId"]),
    "collectInvestigationPackage": ("collectInvestigationPackages", ["deviceId"]),
    "isolateDevice": ("isolateDevices", ["deviceId"]),
}

# The identifiers of the removed responseActions, and the automated action
# property and advanced hunting column each of them stands for
IDENTIFIER_COLUMNS = {
    "deviceId": ("deviceIdColumn", "DeviceId"),
    "accountSid": ("accountSidColumn", "AccountSid"),
    "initiatingProcessAccountSid": ("accountSidColumn", "InitiatingProcessAccountSid"),
    "accountObjectId": ("accountObjectIdColumn", "AccountObjectId"),
    "initiatingProcessAccountObjectId": ("accountObjectIdColumn", "InitiatingProcessAccountObjectId"),
    "sha1": ("sha1Column", "SHA1"),
    "initiatingProcessSHA1": ("sha1Column", "InitiatingProcessSHA1"),
    "sha256": ("sha256Column", "SHA256"),
    "initiatingProcessSHA256": ("sha256Column", "InitiatingProcessSHA256"),
}

# query_period values droid accepts, the ones of the schedule.period Microsoft
# removed, and the schedule.frequency replacing each of them
QUERY_PERIOD_FREQUENCIES = {
    "1H": "PT1H",
    "3H": "PT3H",
    "12H": "PT12H",
    "24H": "P1D",
}


def _duration_seconds(duration):
    """Length of an ISO 8601 duration such as PT1H or P1D, so that two
    spellings of the same frequency (P1D, PT24H) compare equal. A value this
    does not understand is returned as is, and only equals itself."""
    match = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", str(duration))
    if not duration or not match:
        return duration
    days, hours, minutes, seconds = (int(value or 0) for value in match.groups())
    return ((days * 24 + hours) * 60 + minutes) * 60 + seconds


def _tactic_triples(tactics):
    """Reduce alertTemplate tactics to (tactic, technique, sub-technique)
    triples, so that order and empty collections Graph fills in do not count
    as a change"""
    triples = set()
    for tactic in tactics or []:
        for technique in tactic.get("techniques") or [{}]:
            for sub_technique in technique.get("subTechniques") or [None]:
                triples.add((tactic.get("tactic"), technique.get("technique"), sub_technique))
    return triples


def _automated_action_set(automated_actions):
    """Reduce automatedActions to its non-empty actions, ignoring order and the
    empty collections and @odata annotations Graph returns"""
    reduced = {}
    for collection, entries in (automated_actions or {}).items():
        if collection.startswith("@odata") or not entries:
            continue
        reduced[collection] = sorted(
            tuple(sorted(
                (key, tuple(value) if isinstance(value, list) else value)
                for key, value in entry.items()
                if not key.startswith("@odata") and value not in (None, "", [])
            ))
            for entry in entries
        )
    return reduced


class MicrosoftXDRPlatform(AbstractPlatform):

    def __init__(self, parameters: dict, logger_param: dict, export_mssp: bool = False) -> None:
        super().__init__(name="Microsoft XDR")
        self.logger = ColorLogger(__name__, **logger_param)
        self._parameters = parameters
        self._export_mssp = export_mssp
        self._logger_param = logger_param
        self._search_daysago = self._parameters.get("days_ago", 1)
        if not 1 <= self._search_daysago <= 30:
            self.logger.warning("Invalid 'days_ago' value. Expected a value between 1 and 30, but got %d. Defaulting to 1")
            self._search_daysago = 1
        self._query_period_groups = self._parameters.get("rule_parameters", {}).get("query_period_groups")
        if "query_period" not in self._parameters:
            raise Exception('MicrosoftXDRPlatform: "query_period" parameter is required.')
        else:
            self._query_period = self._parameters["query_period"]
        self._warn_about_continuous_query_periods()
        if "auth_cert" in self._parameters:
            self._auth_cert = self._parameters["auth_cert"]
        else:
            self._auth_cert = None
        if "credential_file" in self._parameters:
            try:
                with open(self._parameters["credential_file"], "r") as file:
                    credentials = yaml.safe_load(file)
                self._client_id = credentials["client_id"]
                if not self._auth_cert:
                    self._client_secret = credentials["client_secret"]
                self._tenant_id = credentials["tenant_id"]
                self._cert_pass = self._parameters.get("cert_pass", None)
            except Exception as e:
                raise Exception(f"Error while reading the credential file {e}")
        elif "app" in (self._parameters["search_auth"] or self._parameters["export_auth"]):
            self._tenant_id = self._parameters["tenant_id"]
            self._client_id = self._parameters["client_id"]
            if not self._auth_cert:
                self._client_secret = self._parameters["client_secret"]
            self._cert_pass = self._parameters.get("cert_pass", None)
        elif "default" in (self._parameters["search_auth"] or self._parameters["export_auth"]):
            pass
        else:
            raise Exception('MicrosoftXDRPlatform: "search_auth" and "export_auth" parameters must be one of "default" or "app" or "credential_file".')
        if "alert_prefix" in self._parameters:
            self._alert_prefix = self._parameters["alert_prefix"]
        else:
            self._alert_prefix = None
        if "export_list_mssp" in self._parameters:
            self._export_list_mssp = self._parameters["export_list_mssp"]

        # Conversion callback for re-converting rules with customer-specific filters
        self._convert_rule_callback: Optional[Callable] = None
        
        self._max_throttle_wait = self._parameters.get("max_throttle_wait", DEFAULT_MAX_THROTTLE_WAIT)

        # v1.0 rather than beta: Microsoft does not support beta in production,
        # and changed the custom detection rules there under droid
        self._api_base_url = "https://graph.microsoft.com/v1.0"
        self._token_cache = {}
        # Monotonic deadline per tenant while a throttling window is known to be open
        self._throttled_until = {}

    def _warn_about_continuous_query_periods(self):
        """Say once, when droid starts, that a continuous query_period no longer deploys

        Every rule it applies to fails to export, each with its own error deep
        in the log: a configuration written for the removed schedule.period
        deserves one warning up front naming the setting to change.
        """
        continuous = []
        if str(self._query_period) == "0":
            continuous.append("query_period")
        for group, settings in (self._query_period_groups or {}).items():
            if str(settings.get("query_period")) == "0":
                continuous.append(f"query_period_groups.{group}")
        if continuous:
            self.logger.warning(
                f"Breaking change: the continuous query_period '0', set in {', '.join(continuous)}, "
                "has no documented equivalent in the Graph API custom detection rules. Rules "
                f"using it will fail to export: set one of {list(QUERY_PERIOD_FREQUENCIES)} instead"
            )

    def set_convert_rule_callback(self, callback: Callable) -> None:
        """Set the callback function for converting rules with customer-specific filters

        Args:
            callback: A function that takes (rule_content, rule_file, platform, customer_name) 
                     and returns the converted rule
        """
        self._convert_rule_callback = callback

    def get_export_list_mssp(self) -> list:

        if self._export_list_mssp:
            return self._export_list_mssp
        else:
            self.logger.error("No export_list_mssp found")
            raise

    def run_xdr_search(self, rule_converted, rule_file, tenant_id=None, rule_content=None):
        days_ago = get_search_days_ago(rule_content, self._search_daysago, self.logger, maximum=30)
        payload = {"Query": rule_converted, "Timespan": f"P{days_ago}D"}
        try:
            if tenant_id:
                self.logger.info(
                    f"Searching for rule {rule_file} on tenant {tenant_id}"
                )
            else:
                self.logger.info(
                    f"Searching for rule {rule_file} on tenant {self._tenant_id}"
                )

            results, status_code = self._post(
                url="/security/runHuntingQuery",
                payload=payload,
                tenant_id=tenant_id,
                timeout=HUNTING_QUERY_TIMEOUT,
            )
            time.sleep(2)
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

    def get_rule(self, rule_id, tenant_id=None):
        """Retrieve a scheduled alert rule in Microsoft XDR"""
        try:
            params = {"$filter": f"contains(displayName, '{rule_id}')"}
            rule, status_code = self._get(
                url="/security/rules/detectionRules", params=params, tenant_id=tenant_id
            )
            rule_value = rule.get("value", [])
            if isinstance(rule_value, list) and len(rule_value) > 0:
                time.sleep(6)
                return rule_value[0]
            else:
                self.logger.debug(f"Could not find the rule with id {rule_id}")
                return None
        except Exception as e:
            self.logger.error(f"Error while searching for rule id {rule_id} - {e}")
            raise

    def report_orphan_variant(self, rule_content, rule_file, variant_name, customer_name, tenant_id):
        """Report a rule left behind in a tenant that no longer carries its telemetry

        Dropping a variant from a customer's allowlist stops droid deploying it,
        but whatever was already pushed keeps running there against data the
        customer no longer has. Removing it is deliberately not done here: only
        the operator knows whether the leftover is stale or still wanted, and a
        detection deleted by surprise is worse than one reported.
        """

        try:
            existing_rule = self.get_rule(rule_content["id"], tenant_id)
        except Exception as e:
            self.logger.debug(f"Could not check for an orphan {variant_name} rule in tenant {tenant_id} - error: {e}")
            return

        if existing_rule:
            self.logger.warning(
                f"Orphan rule {rule_file} ({variant_name}) still deployed in tenant {tenant_id} "
                f"for '{customer_name}', which no longer carries that telemetry. "
                "Remove it manually if it is no longer wanted.",
                extra={"rule_file": rule_file, "rule_content": rule_content, "tenant_id": tenant_id},
            )

    def remove_rule(self, rule_content, rule_converted, rule_file):
        """
        Remove a Custom Detection Rule in Microsoft XDR
        """
        if self._export_mssp:
            if self._export_list_mssp:
                error = False
                self.logger.info("Removing rule from designated customers")
                for group, info in self._export_list_mssp.items():
                    tenant_id = info["tenant_id"]
                    self.logger.debug(f"Removing rule in tenant {tenant_id} from {group}")

                    try:
                        existing_rule = self.get_rule(rule_content["id"], tenant_id)
                        if existing_rule:
                            response, status_code = self._delete(
                                url=f"/security/rules/detectionRules/{existing_rule['id']}", tenant_id=tenant_id
                            )
                            if status_code == 204:
                                self.logger.info(f"Rule {rule_file} was successfully deleted from tenant {tenant_id}")
                            else:
                                self.logger.error(
                                    f"Could not delete {rule_file} from tenant {tenant_id} - error: {get_error_message(response)}",
                                    extra={
                                        "rule_file": rule_file,
                                        "rule_converted": rule_converted,
                                        "rule_content": rule_content,
                                    },
                                )
                                error = True
                        else:
                            self.logger.info(f"Rule {rule_file} was already removed from tenant {tenant_id}")
                    except Exception as e:
                        self.logger.error(
                            f"Could not delete the rule {rule_file} from tenant {tenant_id}",
                            extra={
                                "rule_file": rule_file,
                                "rule_converted": rule_converted,
                                "rule_content": rule_content,
                                "error": e,
                            },
                        )
                        error = True
                if error:
                    raise Exception(f"Could not remove the rule {rule_file} from one or more tenants")
            else:
                self.logger.error("Export list not found. Please provide the list of designated customers")
                raise Exception("Export list not found. Please provide the list of designated customers")
        else:
            existing_rule = self.get_rule(rule_content["id"])
            tenant_id = self._tenant_id
            if existing_rule:
                response, status_code = self._delete(
                    url=f"/security/rules/detectionRules/{existing_rule['id']}", tenant_id=tenant_id
                )

                if status_code == 204:
                    self.logger.info(
                        f"Rule {rule_file} was successfully deleted",
                        extra={
                            "rule_file": rule_file,
                            "rule_converted": rule_converted,
                            "rule_content": rule_content,
                        },
                    )
                else:
                    self.logger.error(
                        f"Could not delete {rule_file} - error: {get_error_message(response)}",
                        extra={
                            "rule_file": rule_file,
                            "rule_converted": rule_converted,
                            "rule_content": rule_content,
                        },
                    )
                    raise Exception(f"Could not delete {rule_file} - error: {get_error_message(response)}")
            else:
                self.logger.info(
                    f"Rule {rule_file} was already removed",
                    extra={
                        "rule_file": rule_file,
                        "rule_converted": rule_converted,
                        "rule_content": rule_content,
                    },
                )

    def acquire_token(self, tenant_id=None):
        scope = ["https://graph.microsoft.com/.default"]
        # Check if the custom token hook is set
        custom_token_hook = environ.get('DROID_AZURE_TOKEN_HOOK')
        if custom_token_hook:
            self.logger.debug("Custom token hook selected")
            token, expiration = self._acquire_token_from_hook(custom_token_hook, tenant_id=tenant_id)
            return token, expiration

        if not tenant_id:
            tenant_id = self._tenant_id

        # Check if a valid token already exists for the tenant
        if tenant_id in self._token_cache:
            token, expiration = self._token_cache[tenant_id]
            if datetime.now() < expiration:
                self.logger.debug(f"Using cached token for tenant {tenant_id}")
                return token, expiration

        if self._parameters["search_auth"] == "default":
            self.logger.debug("Default credential selected")
            credential = DefaultAzureCredential()
            token = credential.get_token(*scope).token
            expiration = datetime.now() + timedelta(hours=1)  # Assuming token is valid for 1 hour
        else:
            authority = f"https://login.microsoftonline.com/{tenant_id}"
            if self._auth_cert:
                with open(self._auth_cert, "rb") as file:
                    certificate_data = file.read()
                cert = x509.load_pem_x509_certificate(certificate_data, default_backend())
                fingerprint = cert.fingerprint(hashes.SHA1())
                fingerprint = fingerprint.hex()
                client_credential = {
                    "private_key": certificate_data,
                    "thumbprint": fingerprint,
                    "passphrase": self._cert_pass,
                }
            else:
                client_credential = self._client_secret
            app = ConfidentialClientApplication(
                self._client_id,
                authority=authority,
                client_credential=client_credential,
            )
            result = app.acquire_token_for_client(scopes=scope)
            if "access_token" in result:
                token = result["access_token"]
                expiration = datetime.now() + timedelta(seconds=result["expires_in"])
            else:
                self.logger.error(f'Failed to acquire token: {result["error_description"]}')
                raise Exception(f"Token acquisition failed: {result.get('error', 'Unknown error')}")

        # Store the token and its expiration time in the cache
        self._token_cache[tenant_id] = (token, expiration)
        return token, expiration

    def process_query_period(self, query_period: str, rule_file: str):
        """Translate a query_period into the schedule.frequency Graph expects

        Rules and configurations keep the values of the removed schedule.period,
        so upgrading droid does not mean rewriting them.
        :return: an ISO 8601 duration
        """
        query_period = str(query_period).upper()
        if query_period in QUERY_PERIOD_FREQUENCIES:
            return QUERY_PERIOD_FREQUENCIES[query_period]
        if query_period == "0":
            # TODO: Graph documents no frequency for a continuous (NRT) rule.
            # Refused until the value is confirmed against a tenant, rather than
            # guessing one and deploying a rule that runs on another schedule.
            message = (
                "query_period '0' (continuous) has no documented equivalent in the Graph "
                f"schedule.frequency, use one of {list(QUERY_PERIOD_FREQUENCIES)} - {rule_file}"
            )
        else:
            message = f"query_period must be one of {list(QUERY_PERIOD_FREQUENCIES)}, got '{query_period}' - {rule_file}"
        self.logger.error(message)
        raise ValueError(message)

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
            status = "disabled"
            self.logger.info(f"Disabling the rule {rule_file}")
        else:
            status = "enabled"

        # Handling the severity
        if rule_content["level"] == "critical":
            severity = "high"
        else:
            severity = rule_content["level"]
        tactics = self.build_tactics(rule_content, rule_file)
        try:
            alert_rule = {
                # Graph v1.0 has the client name a rule it creates
                "id": rule_content["id"],
                "displayName": display_name,
                "status": status,
                "queryCondition": {"queryText": rule_converted},
                "detectionAction": {
                    "alertTemplate": {
                        "title": alert_title,
                        "description": rule_content["description"],
                        "severity": severity,
                        "recommendedActions": None,  # TODO: Check if we can add recommended actions, for example the falsepositives?
                        "tactics": tactics,
                    },
                    "organizationalScope": None,  # TODO: Find out what this does
                    "automatedActions": self.parse_actions([], rule_file=rule_file),
                },
            }
        except Exception as e:
            self.logger.error(e)

        # The rule overrides its group, which overrides the configuration. Only
        # the value that wins is translated, so a configuration default with no
        # frequency does not fail the rules that override it.
        query_period = self._query_period
        if self._query_period_groups:
            query_period_group = get_pipeline_group_match(
                rule_content, self._query_period_groups
            )
            if query_period_group:
                self.logger.debug(
                    f"Applying the query_period value from group {query_period_group}"
                )
                query_period = self._query_period_groups[query_period_group]["query_period"]
        query_period = rule_content.get("custom", {}).get("query_period", query_period)
        alert_rule["schedule"] = {
            "frequency": self.process_query_period(query_period, rule_file)
        }

        if "custom" in rule_content:
            if "actions" in rule_content["custom"]:
                alert_rule["detectionAction"]["automatedActions"] = self.parse_actions(
                    rule_content["custom"]["actions"], rule_file=rule_file
                )
            if "impactedAssets" in rule_content["custom"]:
                self.logger.warning(
                    f"custom.impactedAssets is deprecated by Microsoft and no longer pushed - migrate to custom.xdr_entity_mappings - {rule_file}"
                )
            # Not custom.entity_mappings: Sentinel reads that key with its own
            # vocabulary (Account/FullName), which XDR rejects
            if "xdr_entity_mappings" in rule_content["custom"]:
                entityMappings = self.parse_entity_mappings(
                    rule_content["custom"]["xdr_entity_mappings"], rule_file=rule_file
                )
                alert_rule["detectionAction"]["alertTemplate"][
                    "entityMappings"
                ] = entityMappings

        if self._export_mssp:
            if self._export_list_mssp:
                error = False
                self.logger.info("Exporting to designated customers")
                for group, info in self._export_list_mssp.items():

                    tenant_id = info["tenant_id"]
                    customer_name = info.get("customer_name")
                    customer_filter_dir = info.get("customer_filters_directory")

                    if not customer_serves_variant(rule_content, info):
                        variant_name = rule_content["_droid_variant"]["name"]
                        self.logger.debug(
                            f"Skipping tenant {tenant_id} from group id {group}: "
                            f"it does not carry the {variant_name} telemetry"
                        )
                        self.report_orphan_variant(rule_content, rule_file, variant_name,
                                                   customer_name or tenant_id, tenant_id)
                        continue

                    self.logger.debug(
                        f"Exporting to tenant {tenant_id} from group id {group}"
                    )

                    # Check for customer-specific filters and re-convert rule if needed
                    customer_rule_converted = rule_converted
                    customer_alert_rule = alert_rule.copy()

                    if customer_filter_dir and self._convert_rule_callback:
                        self.logger.info(
                            f"Re-converting rule with customer-specific filters for '{customer_name}' from {customer_filter_dir}"
                        )
                        try:
                            customer_rule_converted = self._convert_rule_callback(
                                rule_content, rule_file, self, customer_filter_dir
                            )
                            # Update the alert rule with the customer-specific converted query
                            customer_alert_rule = alert_rule.copy()
                            customer_alert_rule["queryCondition"] = {"queryText": customer_rule_converted}
                            self.logger.debug(
                                f"Successfully re-converted rule for customer '{customer_name}': {customer_rule_converted}"
                            )
                        except Exception as e:
                            self.logger.warning(
                                f"Could not re-convert rule for customer '{customer_name}': {e}. Using default conversion."
                            )

                    try:
                        self.push_detection_rule(
                            alert_rule=customer_alert_rule,
                            rule_content=rule_content,
                            rule_file=rule_file,
                            rule_converted=customer_rule_converted,
                            tenant_id=tenant_id,
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Could not export the rule {rule_file} to tenant {tenant_id} error: {e}",
                            extra={
                                "rule_file": rule_file,
                                "rule_converted": customer_rule_converted,
                                "rule_content": rule_content,
                                "error": e,
                            },
                        )
                        error = True
                if error:
                    raise Exception(f"Could not export the rule {rule_file} to one or more tenants")
            else:
                self.logger.error(
                    "Export list not found. Please provide the list of designated customers"
                )
                raise Exception("Export list not found. Please provide the list of designated customers")
        else:
            try:
                self.push_detection_rule(
                    alert_rule=alert_rule,
                    rule_content=rule_content,
                    rule_file=rule_file,
                    rule_converted=rule_converted,
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

    def build_tactics(self, rule_content, rule_file=None):
        """Build the alertTemplate tactics from the rule's ATT&CK tags

        Sigma tags tactics and techniques separately, without saying which
        technique belongs to which tactic, so every tactic carries every
        technique: nothing tagged is lost. Sub-techniques are grouped under
        their technique.
        """
        tactics = []
        techniques = {}
        for tag in rule_content.get("tags") or []:
            tag = tag.lower().strip()
            if not tag.startswith("attack."):
                continue
            name = tag[len("attack."):]
            if name in MITRE_TACTICS and MITRE_TACTICS[name] not in tactics:
                tactics.append(MITRE_TACTICS[name])
            match = re.fullmatch(r"(t[0-9]{4})(\.[0-9]{3})?", name)
            if match:
                sub_techniques = techniques.setdefault(match.group(1).upper(), [])
                if match.group(2) and name.upper() not in sub_techniques:
                    sub_techniques.append(name.upper())
        if techniques and not tactics:
            self.logger.warning(
                f"Rule {rule_file} has ATT&CK techniques but no tactic tag, its techniques are not pushed"
            )
        return [
            {
                "tactic": tactic,
                "techniques": [
                    {"technique": technique, "subTechniques": list(sub_techniques)}
                    for technique, sub_techniques in techniques.items()
                ],
            }
            for tactic in tactics
        ]

    def rule_differences(self, existing_rule, new_rule):
        """Name the settings where a deployed rule differs from the one droid deploys

        Graph returns every property of a rule, the ones droid leaves unset as
        nulls, empty strings or empty collections, so each setting is
        normalised on both sides rather than compared verbatim.
        """
        existing_template = (existing_rule.get("detectionAction") or {}).get("alertTemplate") or {}
        new_template = new_rule["detectionAction"]["alertTemplate"]

        existing_status = existing_rule.get("status")
        if existing_status == "autoDisabled" and new_rule["status"] == "enabled":
            # Left as Microsoft set it, see push_detection_rule
            existing_status = "enabled"

        compared = {
            "displayName": (existing_rule.get("displayName"), new_rule["displayName"]),
            "status": (existing_status, new_rule["status"]),
            "query": (
                (existing_rule.get("queryCondition") or {}).get("queryText"),
                new_rule["queryCondition"]["queryText"],
            ),
            "frequency": (
                _duration_seconds((existing_rule.get("schedule") or {}).get("frequency")),
                _duration_seconds(new_rule["schedule"]["frequency"]),
            ),
        }
        for field in ("title", "description", "severity", "recommendedActions"):
            compared[field] = (existing_template.get(field) or None, new_template.get(field) or None)
        compared["tactics"] = (
            _tactic_triples(existing_template.get("tactics")),
            _tactic_triples(new_template["tactics"]),
        )
        compared["automatedActions"] = (
            _automated_action_set((existing_rule.get("detectionAction") or {}).get("automatedActions")),
            _automated_action_set(new_rule["detectionAction"]["automatedActions"]),
        )

        # entityMappings is only part of the payload when the rule defines
        # custom.xdr_entity_mappings; otherwise the service auto-derives it and
        # a comparison would flag every rule as changed. The service fills
        # every category and column, unset ones as empty strings, so both
        # sides are reduced to their non-empty (category, column, value)
        # triples before comparing.
        new_mappings = new_template.get("entityMappings")
        if new_mappings is not None:
            compared["entityMappings"] = (
                self._entity_mapping_triples(existing_template.get("entityMappings")),
                self._entity_mapping_triples(new_mappings),
            )

        return [field for field, (deployed, wanted) in compared.items() if deployed != wanted]

    def check_rule_changes(self, existing_rule, new_rule):
        try:
            differences = self.rule_differences(existing_rule, new_rule)
        except Exception as e:
            self.logger.error(f"Error while checking rule changes {e}")
            return True
        if differences:
            self.logger.info(f"Rule '{new_rule['displayName']}' has changed: {', '.join(differences)}")
            return True
        else:
            self.logger.info(
                f"Rule '{new_rule['displayName']}' already exists and is up to date"
            )
            return False

    def push_detection_rule(
        self,
        alert_rule=None,
        rule_content=None,
        rule_file=None,
        rule_converted=None,
        tenant_id=None,
    ):
        existing_rule = self.get_rule(rule_content["id"], tenant_id=tenant_id)
        if existing_rule:
            self.logger.info("Rule already exists")
            # The id of a rule is set when it is created and never changes. A
            # rule created on beta has one Graph chose, not the Sigma id.
            payload = {key: value for key, value in alert_rule.items() if key != "id"}
            if existing_rule.get("status") == "autoDisabled" and alert_rule["status"] == "enabled":
                # Microsoft turns off a rule that keeps failing. Turning it back
                # on every export would only have it fail again: an analyst has
                # to look at it first.
                self.logger.warning(
                    f"Rule {rule_file} was auto-disabled by Microsoft XDR, leaving it disabled - fix and re-enable it on the platform",
                    extra={"rule_file": rule_file, "rule_content": rule_content, "tenant_id": tenant_id},
                )
                payload = {key: value for key, value in payload.items() if key != "status"}
            if not self.check_rule_changes(existing_rule, alert_rule):
                return True
            else:
                api_url = f"/security/rules/detectionRules/{existing_rule['id']}"
                response, status_code = self._patch(
                    url=api_url, payload=payload, tenant_id=tenant_id
                )
        else:
            api_url = "/security/rules/detectionRules"
            response, status_code = self._post(
                url=api_url, payload=alert_rule, tenant_id=tenant_id
            )

        if status_code in (200, 201, 204):
            if isinstance(response, dict) and "error" in response:
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
            self.logger.info(
                f"Successfully exported the rule {rule_file}",
                extra={
                    "rule_file": rule_file,
                    "rule_converted": rule_converted,
                    "rule_content": rule_content,
                },
            )
            time.sleep(6)
            return True

        if status_code == 400:
            reason = f"due to a bad request. {get_error_message(response)}"
        elif status_code == 403:
            reason = f"due to insufficient permissions. {get_error_message(response)}"
        else:
            reason = f"due to an unexpected status code {status_code}. {get_error_message(response)}"

        self.logger.error(
            f"Could not export the rule {rule_file} {reason}",
            extra={
                "rule_file": rule_file,
                "rule_converted": rule_converted,
                "rule_content": rule_content,
                "error": response,
            },
        )
        raise Exception(f"Could not export the rule {rule_file} {reason}")

    def _action_error(self, message, rule_file):
        message = f"{message} - {rule_file}"
        self.logger.error(message)
        return ValueError(message)

    def parse_actions(self, actions, rule_file=None):
        """Build the detectionAction automatedActions payload from custom.actions

        Rules keep the custom.actions of the removed responseActions: an action
        name and the identifier of what it acts on. Graph now takes the query
        column holding that identifier, so each identifier becomes its column.
        Every collection droid manages is sent, empty when unused, so that an
        action removed from a rule is removed from the platform too.
        """
        # TODO: It might be better to have a schema validation for the actions
        automated_actions = {collection: [] for collection, _ in AUTOMATED_ACTIONS.values()}
        for action in actions or []:
            action_name = action.get("action")
            if not action_name:
                raise self._action_error("Action Name is missing from the rule", rule_file)
            if action_name not in AUTOMATED_ACTIONS:
                self.logger.warning(
                    f"Only these actiontypes are allowed: {', '.join(AUTOMATED_ACTIONS)}. {rule_file}"
                )
                continue
            collection, valid_identifiers = AUTOMATED_ACTIONS[action_name]

            identifiers = action.get("identifier")
            if identifiers is None and valid_identifiers == ["deviceId"]:
                # Device actions always act on the device, which the GUI never asks for
                identifiers = "deviceId"
            if not identifiers:
                raise self._action_error(f"Action Identifier is missing from the rule for {action_name}", rule_file)
            if isinstance(identifiers, str):
                identifiers = identifiers.split(",")

            automated_action = {}
            for identifier in identifiers:
                identifier = identifier.strip()
                if identifier not in valid_identifiers:
                    raise self._action_error(
                        f"Identifier for {action_name} must be one of {valid_identifiers}", rule_file
                    )
                column_property, column = IDENTIFIER_COLUMNS[identifier]
                if column_property in automated_action:
                    raise self._action_error(
                        f"Identifiers for {action_name} give {column_property} twice", rule_file
                    )
                automated_action[column_property] = column

            if action_name == "stopAndQuarantineFile":
                # The file is stopped on the device it was seen on
                automated_action["deviceIdColumn"] = IDENTIFIER_COLUMNS["deviceId"][1]
            if action_name == "isolateDevice":
                if action.get("isolationType") not in ("full", "selective"):
                    raise self._action_error(
                        "Isolation Type ('selective' or 'full') is missing from the rule", rule_file
                    )
                automated_action["isolationType"] = action["isolationType"]
            if action_name in ("blockFile", "allowFile") and "deviceGroupNames" in action:
                device_group_names = action["deviceGroupNames"]
                if isinstance(device_group_names, str):
                    device_group_names = [device_group_names]
                automated_action["deviceGroupNames"] = device_group_names if isinstance(device_group_names, list) else []

            automated_actions[collection].append(automated_action)
        return automated_actions

    # Valid column identifiers per entity category, from the Graph
    # entityMappingConfiguration complex type.
    ENTITY_MAPPING_COLUMNS = {
        "accounts": "aadUserIdColumn dnsDomainColumn nameColumn ntDomainColumn sidColumn upnColumn upnSuffixColumn",
        "amazonResources": "amazonResourceIdColumn",
        "azureResources": "resourceIdColumn",
        "cloudApplications": "appIdColumn nameColumn",
        "dns": "domainNameColumn hostIpAddressColumn serverIpColumn",
        "files": "nameColumn sha1Column sha256Column",
        "googleCloudResources": "fullResourceNameColumn",
        "hosts": "deviceIdColumn dnsDomainColumn nameColumn netBiosNameColumn ntDomainColumn",
        "ips": "addressColumn scopeColumn",
        "mailboxes": "primaryAddressColumn",
        "mailClusters": "queryColumn sourceColumn",
        "mailMessages": "networkMessageIdColumn recipientColumn senderColumn subjectColumn",
        "oAuthApplications": "oAuthAppIdColumn",
        "processes": "sha1Column sha256Column",
        "registryValues": "keyColumn valueNameColumn",
        "securityGroups": "distinguishedNameColumn objectIdColumn sidColumn",
        "urls": "addressColumn",
    }

    def _entity_mapping_error(self, message, rule_file):
        message = f"{message} - {rule_file}"
        self.logger.error(message)
        return ValueError(message)

    def parse_entity_mappings(self, entity_mappings, rule_file=None):
        """Build the alertTemplate entityMappings payload from custom.xdr_entity_mappings.

        The YAML has the shape of the Sentinel custom.entity_mappings, with the
        Graph vocabulary instead: a list of entries, each with an entity_type
        and field_mappings of identifier/column_name pairs. Every entry becomes
        one mapping object in the matching category of the Graph
        entityMappingConfiguration.
        """
        entityMappingConfiguration = {}
        for mapping in entity_mappings:
            entity_type = mapping.get("entity_type")
            if entity_type not in self.ENTITY_MAPPING_COLUMNS:
                raise self._entity_mapping_error(
                    f"Entity mappings need 'entity_type' one of {sorted(self.ENTITY_MAPPING_COLUMNS)}",
                    rule_file,
                )
            mapping_entry = {}
            for field in mapping.get("field_mappings") or []:
                identifier = field.get("identifier")
                column_name = field.get("column_name")
                if not identifier or not column_name:
                    raise self._entity_mapping_error(
                        "Entity mapping field_mappings need 'identifier' and 'column_name'",
                        rule_file,
                    )
                if identifier not in self.ENTITY_MAPPING_COLUMNS[entity_type].split():
                    raise self._entity_mapping_error(
                        f"Identifier for {entity_type} must be one of {self.ENTITY_MAPPING_COLUMNS[entity_type].split()}",
                        rule_file,
                    )
                mapping_entry[identifier] = column_name
            if not mapping_entry:
                raise self._entity_mapping_error(
                    "Entity mappings need non-empty 'field_mappings'", rule_file
                )
            entityMappingConfiguration.setdefault(entity_type, []).append(
                mapping_entry
            )
        return entityMappingConfiguration

    @staticmethod
    def _entity_mapping_triples(entity_mappings):
        # Reduce an entityMappingConfiguration to its non-empty
        # (category, column, value) triples, so a payload that only lists the
        # mapped columns compares equal to the service response that fills
        # every category and column with empty strings.
        triples = set()
        if not entity_mappings:
            return triples
        for category, entries in entity_mappings.items():
            for entry in entries:
                for column, value in entry.items():
                    if value:
                        triples.add((category, column, value))
        return triples

    def _acquire_token_from_hook(self, hook_url, tenant_id=None, max_retries=5, retry_delay=10):
        if not tenant_id:
            tenant_id = self._tenant_id

        # Check if a valid token already exists for the tenant
        if tenant_id in self._token_cache:
            token, expiration = self._token_cache[tenant_id]
            if datetime.now() < expiration:
                self.logger.debug(f"Using cached token for tenant {tenant_id}")
                return token, expiration

        # Replace {TENANT_ID} with the actual tenant_id if it exists in the URL
        if '{TENANT_ID}' in hook_url:
            hook_url = hook_url.replace('{TENANT_ID}', tenant_id)

        headers = get_token_hook_headers()

        for attempt in range(max_retries):
            try:
                self.logger.debug(f"Requesting token from URL hook (attempt {attempt + 1}/{max_retries})")
                response = requests.get(hook_url, timeout=(10, 30), headers=headers)
                self.logger.debug(f"Token hook responded with status {response.status_code}")
                response.raise_for_status()
                token_data = response.json()
                token = token_data.get("access_token")
                if not token:
                    self.logger.error("Access token not found in the response")
                    raise Exception("Access token not found in the response")
                expiration = datetime.now() + timedelta(seconds=3600)

                # Store the token and its expiration time in the cache
                self._token_cache[tenant_id] = (token, expiration)
                self.logger.debug("Successfully acquired token from hook")
                return token, expiration
            except requests.exceptions.ConnectTimeout:
                self.logger.error(f"Attempt {attempt + 1}/{max_retries}: connection to token hook timed out")
                if attempt < max_retries - 1:
                    self.logger.debug(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    raise Exception("Token hook unreachable: connection timed out after all retries")
            except requests.exceptions.ReadTimeout:
                self.logger.error(f"Attempt {attempt + 1}/{max_retries}: token hook did not respond in time (read timeout)")
                if attempt < max_retries - 1:
                    self.logger.debug(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    raise Exception("Token hook unresponsive: read timed out after all retries")
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Attempt {attempt + 1}/{max_retries} failed to acquire token from custom hook: {str(e)}")
                if attempt < max_retries - 1:
                    self.logger.debug(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    self.logger.error(f"Failed to acquire token from custom hook after {max_retries} attempts")
                    raise Exception(f"Token acquisition from custom hook failed: {str(e)}")

    def _throttling_details(self, response) -> str:
        """Summarise why Graph throttled the request, for --debug troubleshooting

        Graph names the limit it enforced in the error body and reports the consumed
        budget through the rate-limit headers. Neither is guaranteed to be present, so
        every lookup here is best effort and the caller always gets a printable string.
        """
        details = []

        try:
            error = response.json().get("error") or {}
        except ValueError:  # a gateway may answer 429 with something other than JSON
            error = {}
        inner_error = error.get("innerError") or {}

        code = error.get("code") or inner_error.get("code")
        if code:
            details.append(f"code={code}")

        message = error.get("message") or inner_error.get("message")
        if message:
            details.append(f"message={message}")

        # Both ids are what Microsoft support asks for when a limit looks wrong
        request_id = inner_error.get("request-id") or response.headers.get("request-id")
        if request_id:
            details.append(f"request-id={request_id}")
        client_request_id = response.headers.get("client-request-id")
        if client_request_id:
            details.append(f"client-request-id={client_request_id}")

        details.extend(
            f"{header}={response.headers[header]}"
            for header in THROTTLING_HEADERS
            if response.headers.get(header)
        )

        return ", ".join(details) if details else "no details returned by Graph"

    def _parse_retry_after(self, response) -> Optional[float]:
        """Extract the Retry-After delay advertised by Microsoft Graph

        Graph documents Retry-After as the fastest way to recover from throttling
        (https://learn.microsoft.com/en-us/graph/throttling). The header holds either a
        number of seconds or an HTTP-date. Returns None when the header is absent or
        cannot be understood, so the caller can fall back to its own backoff.
        """
        header = response.headers.get("Retry-After")
        if not header:
            return None

        try:
            delay = float(header)
        except (TypeError, ValueError):
            try:
                retry_date = parsedate_to_datetime(header)
            except (TypeError, ValueError):
                self.logger.warning(f"Unparsable Retry-After header '{header}', falling back to the configured delay")
                return None
            if retry_date.tzinfo is None:  # an HTTP-date without offset is UTC
                retry_date = retry_date.replace(tzinfo=timezone.utc)
            delay = (retry_date - datetime.now(timezone.utc)).total_seconds()

        if delay > MAX_RETRY_AFTER_SECONDS:
            # Never clamp silently: retrying before the window Graph named just earns
            # another 429, and every retry accrues against the tenant quota
            self.logger.warning(f"Graph asked to wait {delay:.0f} seconds, which is implausibly long, capping at {MAX_RETRY_AFTER_SECONDS} seconds")
            return float(MAX_RETRY_AFTER_SECONDS)

        return max(0.0, delay)

    def _wait_out_throttling(self, tenant_id, method, url, api_url, throttle_waited, max_throttle_wait) -> float:
        """Sleep off a throttling window already known to be open for this tenant

        Graph quotas such as CpuQuotaExceeded are tenant-wide, so once one request has
        been told to back off, every later one is refused for the same window. Holding
        the whole platform here keeps a run over many rules from rediscovering the same
        limit with a 429 per rule, each of which still accrues against the quota.

        Returns the seconds spent waiting, and raises when that wait does not fit the
        remaining budget.
        """
        deadline = self._throttled_until.get(tenant_id)
        if deadline is None:
            return 0.0

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            del self._throttled_until[tenant_id]
            return 0.0

        # Refuse a wait we cannot afford before spending any of it, and without
        # sending a request that is certain to come back throttled
        if throttle_waited + remaining > max_throttle_wait:
            self.logger.error(f"{method} {api_url} needs {remaining:.0f} more seconds of throttling wait, over the {max_throttle_wait}s budget ({throttle_waited:.0f}s already spent), giving up")
            raise Exception(f"Graph API request throttled beyond the {max_throttle_wait}s wait budget: {method} {url}")

        self.logger.warning(f"Tenant is throttled for another {remaining:.0f} seconds, waiting it out before {method} {api_url}")
        time.sleep(remaining)
        del self._throttled_until[tenant_id]
        return remaining

    def _request_with_retries(self, method, url=None, payload=None, headers=None, params=None, tenant_id=None, timeout=60, retry_delay=30, max_retries=5, max_throttle_retries=10, max_throttle_wait=None):
        api_url = self._api_base_url + url

        if max_throttle_wait is None:
            max_throttle_wait = self._max_throttle_wait

        if not tenant_id:
            tenant_id = self._tenant_id

        # Check if the token is about to expire or has expired for the tenant
        if tenant_id not in self._token_cache or datetime.now() >= self._token_cache[tenant_id][1]:
            self.logger.debug(f"Refreshing the token for tenant {tenant_id} since it has expired or does not exist")
            token, expiration = self.acquire_token(tenant_id)
            self._token_cache[tenant_id] = (token, expiration)

        token, _ = self._token_cache[tenant_id]
        request_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        if headers:
            request_headers.update(headers)

        attempt = 0
        throttle_attempt = 0
        throttle_waited = 0.0
        token_refreshed = False
        while attempt < max_retries:
            try:
                throttle_waited += self._wait_out_throttling(tenant_id, method, url, api_url, throttle_waited, max_throttle_wait)

                self.logger.debug(f"{method} {api_url} (attempt {attempt + 1}/{max_retries})")
                if method == "GET":
                    response = requests.get(api_url, headers=request_headers, params=params, timeout=timeout)
                elif method == "POST":
                    response = requests.post(api_url, headers=request_headers, json=payload, timeout=timeout)
                elif method == "PATCH":
                    response = requests.patch(api_url, headers=request_headers, json=payload, timeout=timeout)
                elif method == "DELETE":
                    response = requests.delete(api_url, headers=request_headers, params=params, timeout=timeout)
                else:
                    self.logger.error(f"Unsupported HTTP method: {method}")
                    return None, 500

                if response.status_code == 204:
                    return {}, response.status_code
                elif response.status_code == 429:
                    # Throttling gets its own budget: Graph asks clients to keep retrying
                    # on the advertised delay rather than to give up, and a burst of 429s
                    # should not consume the retries reserved for real failures.
                    throttle_attempt += 1
                    self.logger.debug(f"Throttled on {method} {api_url}: {self._throttling_details(response)}")
                    if throttle_attempt > max_throttle_retries:
                        self.logger.error(f"{method} {api_url} still throttled after {max_throttle_retries} retries, giving up")
                        raise Exception(f"Graph API request throttled after {max_throttle_retries} retries: {method} {url}")
                    delay = self._parse_retry_after(response)
                    if delay is None:
                        delay = min(retry_delay * (2 ** (throttle_attempt - 1)), MAX_RETRY_AFTER_SECONDS)
                        self.logger.warning(f"Rate limit reached with no Retry-After header, backing off {delay:.0f} seconds (throttle retry {throttle_attempt}/{max_throttle_retries})")
                    else:
                        self.logger.warning(f"Rate limit reached, honouring Retry-After of {delay:.0f} seconds (throttle retry {throttle_attempt}/{max_throttle_retries})")

                    # Record the window for the whole tenant rather than sleeping here:
                    # the gate at the top of the loop serves this retry, and every later
                    # request for the tenant waits on it instead of earning its own 429
                    self._throttled_until[tenant_id] = time.monotonic() + delay
                elif 500 <= response.status_code < 600:
                    attempt += 1
                    delay = self._parse_retry_after(response)  # 503 commonly carries one too
                    if delay is None:
                        delay = retry_delay
                    self.logger.warning(f"Server error {response.status_code}, retrying in {delay:.0f} seconds (attempt {attempt}/{max_retries})")
                    if attempt < max_retries:
                        time.sleep(delay)
                elif response.status_code == 401 and not token_refreshed:
                    self.logger.warning(f"Token expired for tenant {tenant_id}, refreshing token")
                    token, expiration = self.acquire_token(tenant_id)
                    self._token_cache[tenant_id] = (token, expiration)
                    request_headers["Authorization"] = f"Bearer {token}"
                    token_refreshed = True  # only refresh once to avoid infinite loop
                else:
                    return response.json(), response.status_code
            except requests.exceptions.Timeout:
                attempt += 1
                self.logger.warning(f"{method} {api_url} timed out after {timeout}s (attempt {attempt}/{max_retries})")
                if attempt < max_retries:
                    time.sleep(retry_delay)
            except requests.exceptions.ConnectionError as e:
                attempt += 1
                self.logger.error(f"{method} {api_url} connection error (attempt {attempt}/{max_retries}): {str(e)}")
                if attempt < max_retries:
                    time.sleep(retry_delay)
            except requests.exceptions.RequestException as e:
                self.logger.error(f"An error occurred: {str(e)}")
                return None, 500

        self.logger.error(f"{method} {api_url} failed after {max_retries} attempts, giving up")
        raise Exception(f"Graph API request failed after {max_retries} attempts: {method} {url}")

    def _get(self, url=None, headers=None, params=None, tenant_id=None, timeout=120, retry_delay=60):
        return self._request_with_retries(
            method="GET",
            url=url,
            headers=headers,
            params=params,
            tenant_id=tenant_id,
            timeout=timeout,
            retry_delay=retry_delay,
        )

    def _post(self, url=None, payload=None, headers=None, params=None, tenant_id=None, timeout=120, retry_delay=60):
        return self._request_with_retries(
            method="POST",
            url=url,
            payload=payload,
            headers=headers,
            params=params,
            tenant_id=tenant_id,
            timeout=timeout,
            retry_delay=retry_delay,
        )

    def _patch(self, url=None, payload=None, headers=None, params=None, tenant_id=None, timeout=120, retry_delay=60):
        return self._request_with_retries(
            method="PATCH",
            url=url,
            payload=payload,
            headers=headers,
            params=params,
            tenant_id=tenant_id,
            timeout=timeout,
            retry_delay=retry_delay,
        )

    def _delete(self, url=None, headers=None, params=None, tenant_id=None, timeout=120, retry_delay=60):
        return self._request_with_retries(
            method="DELETE",
            url=url,
            headers=headers,
            params=params,
            tenant_id=tenant_id,
            timeout=timeout,
            retry_delay=retry_delay,
        )
