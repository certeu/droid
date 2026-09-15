"""
Module for HarfangLab
"""

import requests
import yaml

from droid.abstracts import AbstractPlatform
from droid.color import ColorLogger

# The HarfangLab Sigma backend emits transformed Sigma YAML rather than a query
# language, so the converted rule is pushed verbatim into the "content" field.
SIGMA_RULE_PATH = "/data/threat_intelligence/SigmaRule/"

# Correlation rules live in their own collection, backed by their own source.
# HarfangLab resolves the rules a correlation depends on from the YAML itself,
# so the referenced atomic rules travel along in the same document.
CORRELATION_RULE_PATH = "/data/threat_intelligence/CorrelationRule/"

# Maximum length accepted by the API for the rule name
NAME_MAX_LENGTH = 100

# Number of rules fetched per page when looking a rule up
SEARCH_PAGE_SIZE = 100

# requests advertises itself by default, which stands out in the console access
# logs. Overridable through the "user_agent" platform setting.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36"
)

GLOBAL_STATES = ["alert", "backend_alert", "block", "disabled", "quarantine"]
HL_STATUSES = ["experimental", "stable", "testing"]
RULE_LEVELS = ["critical", "high", "informational", "low", "medium"]

# HarfangLab tells rules apart on their Sigma id, not on their name, and rules
# are looked up within a single source. A rule holding the same id in another
# source is therefore invisible to the lookup but still refused on creation.
DUPLICATE_ID_HINT = (
    "a rule with the same Sigma id already exists on the platform, outside of the source "
    "droid is exporting to"
)

# HarfangLab does not store "global_state" next to the agent flags, it derives
# each from the other. A payload holding a combination it would never produce
# comes back rewritten, which reads as a change on the next export and has the
# rule updated on every run, so the state is settled here before it is sent.
AGENT_FLAGS_BY_STATE = {
    "disabled": (False, False),
    "alert": (False, False),
    "block": (True, False),
    "quarantine": (True, True),
}


def normalise_sigma_content(content):
    """Parse a Sigma document so two revisions can be compared structurally

    HarfangLab re-serialises the YAML it stores, so a plain string comparison
    reports differences on rules that are in fact identical. A correlation rule
    carries the rules it depends on in the same document, hence the multi
    document parsing.

    Return: the list of parsed documents, or the stripped string when it cannot
    be parsed
    """

    try:
        parsed = list(yaml.safe_load_all(content))
    except yaml.YAMLError:
        return content.strip()

    if not any(document is not None for document in parsed):
        return content.strip()

    return parsed


def prepare_correlation_content(content):
    """Adapt a converted correlation document to the HarfangLab Sigma dialect

    HarfangLab rejects a correlation document on two counts the backend does not
    cater for yet:
      - a null valued correlation key, such as the "group-by" the backend always
        emits, is refused outright ("invalid type: unit value, expected a
        sequence")
      - every Sigma rule embedded next to the correlation must carry
        "generate: false", otherwise it is also compiled as a standalone rule

    Both adjustments are idempotent, so they turn into no-ops once the backend
    emits the dialect itself.

    Return: the adapted document, or the content unchanged when it cannot be parsed
    """

    try:
        documents = list(yaml.safe_load_all(content))
    except yaml.YAMLError:
        return content

    if not all(isinstance(document, dict) for document in documents):
        return content

    for document in documents:
        correlation = document.get("correlation")

        if isinstance(correlation, dict):
            for key in [key for key, value in correlation.items() if value is None]:
                correlation.pop(key)
        else:
            document["generate"] = False

    return "---\n".join(
        yaml.safe_dump(document, sort_keys=False, default_flow_style=False)
        for document in documents
    )


class HarfangLabPlatform(AbstractPlatform):

    def __init__(self, parameters: dict, logger_param: dict) -> None:

        super().__init__(name="HarfangLab")

        self._parameters = parameters

        self.logger = ColorLogger(__name__, **logger_param)

        if "url" not in self._parameters:
            raise ValueError("HarfangLabPlatform: 'url' is not set.")

        if "token" not in self._parameters:
            raise ValueError("HarfangLabPlatform: 'token' is not set. Use: export DROID_HARFANGLAB_TOKEN=<value>")

        if "source_id" not in self._parameters:
            raise ValueError("HarfangLabPlatform: 'source_id' is not set.")

        self._url = self._parameters["url"].rstrip("/")
        self._token = self._parameters["token"]
        self._source_id = self._parameters["source_id"]
        # Correlation rules are stored in a separate source, only needed when
        # correlation rules are actually exported
        self._source_id_correlation = self._parameters.get("source_id_correlation")
        self._timeout = self._parameters.get("timeout", 120)

        if "tls_verify" not in self._parameters:
            self.logger.debug("HarfangLabPlatform: 'tls_verify' is not set, using default of True.")
            self._parameters["tls_verify"] = True

        self._tls_verify = self._parameters["tls_verify"]
        self._alert_prefix = self._parameters.get("alert_prefix")
        self._user_agent = self._parameters.get("user_agent", DEFAULT_USER_AGENT)

        self._global_state = self._validate_choice(
            "global_state", self._parameters.get("global_state", "alert"), GLOBAL_STATES
        )
        self._hl_status = self._validate_choice(
            "hl_status", self._parameters.get("hl_status", "testing"), HL_STATUSES
        )
        self._block_on_agent = self._parameters.get("block_on_agent", False)
        self._quarantine_on_agent = self._parameters.get("quarantine_on_agent", False)

        self._api_base_url = self._url + "/api"

    @staticmethod
    def _validate_choice(name, value, allowed):
        """Ensure a configured value belongs to the enum accepted by the API"""

        if value not in allowed:
            raise ValueError(
                f"HarfangLabPlatform: invalid '{name}' value '{value}'. Expected one of: {', '.join(allowed)}"
            )

        return value

    @staticmethod
    def is_correlation_rule(rule_content):
        """Tell a Sigma correlation rule from an atomic one

        Return: True when the rule is a correlation rule
        """

        return "correlation" in rule_content

    def _endpoint(self, correlation):
        """Resolve the collection a rule belongs to

        Return: a tuple with the API path and the source id to use
        """

        if not correlation:
            return SIGMA_RULE_PATH, self._source_id

        if not self._source_id_correlation:
            raise ValueError(
                "HarfangLabPlatform: 'source_id_correlation' is not set, it is required to "
                "export correlation rules. Use: export DROID_HARFANGLAB_SOURCE_ID_CORRELATION=<value>"
            )

        return CORRELATION_RULE_PATH, self._source_id_correlation

    def _headers(self):
        return {
            "Authorization": f"Token {self._token}",
            "Content-Type": "application/json",
            "User-Agent": self._user_agent,
        }

    def _request(self, method, path, params=None, payload=None):
        """Send a request to the HarfangLab API

        Return: a tuple with the decoded body (None on 204) and the status code
        """

        response = requests.request(
            method,
            self._api_base_url + path,
            headers=self._headers(),
            params=params,
            json=payload,
            verify=self._tls_verify,
            timeout=self._timeout,
        )

        if response.status_code == 204 or not response.content:
            return None, response.status_code

        try:
            return response.json(), response.status_code
        except ValueError:
            return response.text, response.status_code

    def get_rule(self, rule_id, correlation=False):
        """Retrieve a Sigma or a correlation rule in HarfangLab

        The Sigma rule identifier is exposed as the read-only "rule_id" field and
        cannot be filtered on, so the search term is used to narrow the list down
        before matching exactly on the client side.

        Return: the rule as a dict or None when it is not found
        """

        path, source_id = self._endpoint(correlation)
        offset = 0

        while True:
            params = {
                "source_id": source_id,
                "search": rule_id,
                "limit": SEARCH_PAGE_SIZE,
                "offset": offset,
            }

            try:
                results, status_code = self._request("GET", path, params=params)
            except Exception as e:
                self.logger.error(f"Error while searching for rule id {rule_id} - {e}")
                raise

            if status_code != 200 or not isinstance(results, dict):
                raise Exception(f"Could not search for the rule id {rule_id} - {status_code} {results}")

            page = results.get("results", [])

            for rule in page:
                if rule.get("rule_id") == rule_id:
                    return rule

            # The search is a fuzzy one, so the rule can sit on any page
            offset += len(page)
            if not page or not results.get("next") or offset >= results.get("count", 0):
                break

        self.logger.debug(f"Could not find the rule with id {rule_id}")

        return None

    def get_rule_name(self, rule_content, rule_file=None):
        """Build the rule name displayed in HarfangLab

        Return: a str truncated to the length accepted by the API
        """

        if self._alert_prefix:
            name = self._alert_prefix + " - " + rule_content["title"]
        else:
            name = rule_content["title"]

        if len(name) > NAME_MAX_LENGTH:
            self.logger.warning(
                f"The rule name exceeds {NAME_MAX_LENGTH} characters and was truncated for {rule_file}"
            )
            # HarfangLab trims the name it stores, so a cut landing on a space
            # would otherwise never compare equal to what was sent
            name = name[:NAME_MAX_LENGTH].strip()

        return name

    def get_rule_parameters(self, rule_content):
        """Resolve the rule state, applying any per-rule override

        The platform configuration holds the defaults, a rule can override them
        through its "custom.harfanglab" section.

        Return: a dict with the state fields expected by the API
        """

        custom = rule_content.get("custom", {})
        overrides = custom.get("harfanglab", {})

        global_state = self._validate_choice(
            "global_state", overrides.get("global_state", self._global_state), GLOBAL_STATES
        )
        if global_state == "backend_alert":
            # Advertised by the API schema, but stored as "alert" by the
            # platform, which would have the rule updated on every export
            self.logger.warning(
                "The global state 'backend_alert' is not honoured by HarfangLab, using 'alert'"
            )
            global_state = "alert"

        block_on_agent = overrides.get("block_on_agent", self._block_on_agent)
        quarantine_on_agent = overrides.get("quarantine_on_agent", self._quarantine_on_agent)
        enabled = not custom.get("disabled", False) and global_state != "disabled"

        # The agent flags read as a shorthand raising the state, so that asking
        # for a block on a rule left in the default "alert" state is honoured
        # rather than silently dropped
        if not enabled:
            global_state = "disabled"
        elif quarantine_on_agent:
            global_state = "quarantine"
        elif block_on_agent:
            global_state = "block"

        block_on_agent, quarantine_on_agent = AGENT_FLAGS_BY_STATE[global_state]

        return {
            "global_state": global_state,
            "hl_status": self._validate_choice(
                "hl_status", overrides.get("hl_status", self._hl_status), HL_STATUSES
            ),
            "block_on_agent": block_on_agent,
            "quarantine_on_agent": quarantine_on_agent,
            "enabled": enabled,
        }

    def get_rule_content(self, rule_content, rule_converted):
        """Give the Sigma document as it is pushed to the platform

        Used by the integrity check too, so that it compares what was actually
        sent rather than the raw output of the backend.

        Return: a str holding one or more Sigma documents
        """

        if not self.is_correlation_rule(rule_content):
            return rule_converted

        return prepare_correlation_content(rule_converted)

    def build_rule_payload(self, rule_content, rule_converted, rule_file):
        """Build the body sent to the SigmaRule or CorrelationRule endpoint

        Return: a dict ready to be serialised as JSON
        """

        _, source_id = self._endpoint(self.is_correlation_rule(rule_content))

        payload = {
            "name": self.get_rule_name(rule_content, rule_file),
            "content": self.get_rule_content(rule_content, rule_converted),
            "source_id": source_id,
        }

        payload.update(self.get_rule_parameters(rule_content))

        # Both fields are always sent so that an update clears the value left
        # over on the platform when it is dropped from the rule
        level = rule_content.get("level")
        if level and level not in RULE_LEVELS:
            self.logger.warning(f"Unknown level '{level}', not overriding the rule level for {rule_file}")
            level = None

        payload["rule_level_override"] = level
        payload["references"] = rule_content.get("references", [])

        return payload

    def content_matches(self, existing_content, new_content):
        """Compare two Sigma documents regardless of their serialisation

        Return: True when both documents hold the same rule
        """

        return normalise_sigma_content(existing_content or "") == normalise_sigma_content(new_content or "")

    def check_rule_changes(self, existing_rule, new_rule):
        """Compare a rule on the platform with the one about to be exported

        Return: True when the rule must be updated
        """

        if not self.content_matches(existing_rule.get("content"), new_rule["content"]):
            self.logger.info(f"Rule '{new_rule['name']}' content has changed")
            return True

        fields = [
            "name",
            "enabled",
            "global_state",
            "hl_status",
            "block_on_agent",
            "quarantine_on_agent",
            "rule_level_override",
            "references",
        ]

        for field in fields:
            if field not in new_rule:
                continue
            existing_value = existing_rule.get(field)
            new_value = new_rule[field]
            # An unset value is reported either as null or as an empty list
            # depending on the field, both mean the same to us
            if not existing_value and not new_value:
                continue
            if existing_value != new_value:
                self.logger.info(f"Rule '{new_rule['name']}' has changed on the field {field}")
                return True

        return False

    def check_upload_status(self, response, rule_file):
        """Raise when the API reports a failure in a creation response

        The creation endpoint answers 201 even when the Sigma content was
        rejected, the outcome is carried by the "status" list instead.
        """

        if not isinstance(response, dict):
            return

        for status in response.get("status", []):
            # "status" is optional and defaults to false, so a missing key is a
            # failure just as much as an explicit false one
            if not status.get("status"):
                code = status.get("code", "unknown_error")
                details = status.get("content", "")

                if code == "duplicate_rule":
                    details = f"{details} - {DUPLICATE_ID_HINT}"

                raise Exception(f"The rule {rule_file} was rejected by HarfangLab ({code}): {details}")

    def check_rule_errors(self, rule, rule_file):
        """Log the parsing feedback returned by the HarfangLab Sigma engine"""

        if not isinstance(rule, dict):
            return

        if rule.get("errors"):
            raise Exception(f"HarfangLab could not parse the rule {rule_file}: {rule['errors']}")

        if rule.get("warnings"):
            self.logger.warning(f"HarfangLab reported warnings for the rule {rule_file}: {rule['warnings']}")

    def create_rule(self, rule_content, rule_converted, rule_file):
        """Create or update a Sigma or a correlation rule in HarfangLab"""

        correlation = self.is_correlation_rule(rule_content)
        path, _ = self._endpoint(correlation)
        payload = self.build_rule_payload(rule_content, rule_converted, rule_file)

        try:
            existing_rule = self.get_rule(rule_content["id"], correlation)

            if existing_rule:
                if not self.check_rule_changes(existing_rule, payload):
                    self.logger.info(f"Rule '{payload['name']}' already exists and is up to date")
                    return

                rule, status_code = self._request(
                    "PATCH", f"{path}{existing_rule['id']}/", payload=payload
                )

                if status_code != 200:
                    raise Exception(f"Could not update the rule - {status_code} {rule}")

                self.check_rule_errors(rule, rule_file)
            else:
                response, status_code = self._request("POST", path, payload=payload)

                if status_code not in (200, 201):
                    # The lookup is scoped to one source, so a rule holding the
                    # same Sigma id elsewhere only shows up here
                    if status_code == 400 and isinstance(response, dict) and response.get("id"):
                        raise Exception(
                            f"Could not create the rule - {response['id']} - {DUPLICATE_ID_HINT}"
                        )
                    raise Exception(f"Could not create the rule - {status_code} {response}")

                self.check_upload_status(response, rule_file)

                # The creation response carries no parsing feedback, unlike the
                # update one, so the rule is read back to report it
                self.check_rule_errors(self.get_rule(rule_content["id"], correlation), rule_file)

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

    def remove_rule(self, rule_content, rule_converted=None, rule_file=None):
        """Remove a Sigma or a correlation rule in HarfangLab"""

        correlation = self.is_correlation_rule(rule_content)
        path, _ = self._endpoint(correlation)

        try:
            existing_rule = self.get_rule(rule_content["id"], correlation)

            if not existing_rule:
                self.logger.info(f"The rule {rule_file} is already absent from the platform")
                return

            response, status_code = self._request("DELETE", f"{path}{existing_rule['id']}/")

            # Both collections refuse to drop a rule another correlation rule
            # still depends on, each with its own error code
            if status_code == 400 and isinstance(response, dict) and response.get("code") in (
                "linked_sigma_rule",
                "linked_correlation_rule",
            ):
                linked = ", ".join(
                    correlation_rule.get("correlation_rule_name", "")
                    for correlation_rule in response.get("linked_correlation", [])
                )
                raise Exception(
                    f"The rule is used by one or more correlation rules and cannot be deleted: {linked}"
                )

            if status_code not in (200, 204):
                raise Exception(f"Could not remove the rule - {status_code} {response}")

            self.logger.info(
                f"Successfully removed the rule {rule_file}",
                extra={"rule_file": rule_file, "rule_content": rule_content},
            )
        except Exception as e:
            self.logger.error(
                f"Could not remove the rule {rule_file}",
                extra={"rule_file": rule_file, "rule_content": rule_content, "error": e},
            )
            raise
