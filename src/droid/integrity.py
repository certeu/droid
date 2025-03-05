"""
Module handling the integrity check of the rules on the platforms.
"""
import yaml

from pathlib import Path
from droid.platforms.splunk import SplunkPlatform
from droid.platforms.sentinel import SentinelPlatform
from droid.platforms.elastic import ElasticPlatform
from droid.platforms.ms_xdr import MicrosoftXDRPlatform
from droid.color import ColorLogger
from droid.export import post_rule_content

def load_rule(rule_file):

    with open(rule_file, "r") as stream:
        try:
            object = list(yaml.safe_load_all(stream))[0]
            return object
        except yaml.YAMLError as exc:
            print(exc)
            print("Error reading {0}".format(rule_file))
            error = True
            return error

def check_rule_removed(rule_content, rule_file, saved_search, logger, error):
    is_removed = rule_content.get("custom", {}).get("removed")

    if not saved_search:
        if is_removed:
            logger.info(f"The rule {rule_file} is marked as removed and not found on the platform as expected")
            error = False
        else:
            logger.error(f"Rule not found {rule_file}")
            error = True
        return error
    return None

def integrity_rule_splunk(rule_converted, rule_content, platform: SplunkPlatform, rule_file, parameters, logger, error):
    try:
        saved_search: dict = platform.search_savedsearch(rule_content)
        # Mapping rule_content with a Splunk saved search properties
        mapping = {
            "detection": "search",
            "description": "description"
        }
    except Exception as e:
        logger.error(f"Couldn't check the integrity for the rule {rule_file} - error {e}")
        error = True
        return error

    error = check_rule_removed(rule_content, rule_file, saved_search, logger, error)
    if error is not None:
        return error

    logger.info(f"Successfully retrieved the rule {rule_file}")

    result = {
        "description": saved_search["description"],
        "search": saved_search["search"]
    }

    rule_content["detection"] = rule_converted

    for key in mapping:

        rule_key = key
        result_key = mapping[key]

        if rule_content.get(rule_key) == result.get(result_key):
            logger.debug(f"{rule_key} in rule_content matches {result_key} in result")
        else:
            logger.error(f"{rule_key} in rule_content does not match {result_key} in result")
            error = True

    # Check if disabled
    is_disabled = rule_content.get("custom", {}).get("disabled")

    if saved_search["disabled"] == "0":
        is_enabled = True
    else:
        is_enabled = False

    if is_disabled is True and not is_enabled:
        logger.info("The rule is disabled as expected")
    elif is_disabled is True and is_enabled:
        logger.error("The rule is not disabled on the platform")
        error = True
    elif is_disabled is None and not is_enabled:
        logger.error("The rule is not enabled on the platform")
        error = True
    elif is_disabled is None and is_enabled:
        logger.info("The rule is enabled as expected")

    if error:
        return error

def integrity_rule_sentinel_mssp(rule_converted, rule_content, platform: SentinelPlatform, rule_file, parameters, logger, error):

    try:
        export_list = platform.get_export_list_mssp()
    except Exception as e:
        logger.error(f"Couldn't get the export list for the designated customers - error {e}")
        return error

    logger.info("Integrity check for designated customers")

    error_occured = False

    for group, info in export_list.items():

        tenant_id = info['tenant_id']
        subscription_id = info['subscription_id']
        resource_group_name = info['resource_group_name']
        workspace_name = info['workspace_name']

        logger.debug(f"Processing rule on {workspace_name} from group id {group}")
        try:
            saved_search: dict = platform.get_rule_mssp(
                rule_content, rule_file, tenant_id,
                subscription_id, resource_group_name,
                workspace_name
            )
        except Exception as e:
            logger.error(f"Couldn't check the integrity for the rule {rule_file} on workspace {workspace_name} from {group} - error {e}")
            return error

        error = check_rule_removed(rule_content, rule_file, saved_search, logger, error)
        if error is not None:
            return error

        error = integrity_rule_sentinel(rule_converted, rule_content, platform, rule_file, parameters, logger, error, saved_search=saved_search)

        if error:
            error_occured = True

    if error_occured:
        return error

def integrity_rule_sentinel(
        rule_converted, rule_content, platform: SentinelPlatform,
        rule_file, parameters, logger,
        error, saved_search=None
):
    try:
        if not saved_search:
            saved_search: dict = platform.get_rule(rule_content, rule_file)
    except Exception as e:
        logger.error(f"Couldn't check the integrity for the rule {rule_file} - error {e}")
        return error

    mapping = {
        "id": "name",
        "detection": "query",
        "description": "description"
    }

    error = check_rule_removed(rule_content, rule_file, saved_search, logger, error)
    if error is not None:
        return error

    logger.info(f"Successfully retrieved the rule {rule_file}")

    result = {
        "name": saved_search.name,
        "description": saved_search.description,
        "query": saved_search.query
    }

    rule_content["detection"] = rule_converted

    for key in mapping:
        rule_key = key
        result_key = mapping[key]

        if rule_content.get(rule_key) == result.get(result_key):
            logger.debug(f"{rule_key} in rule_content matches {result_key} in result")
        else:
            logger.error(f"{rule_key} in rule_content does not match {result_key} in result")
            error = True

    # Check if disabled
    is_disabled = rule_content.get("custom", {}).get("disabled")

    if is_disabled and not saved_search.enabled:
        logger.info("The rule is disabled as expected")
    elif is_disabled and saved_search.enabled:
        logger.error("The rule is not disabled on the platform")
        error = True
    elif is_disabled is None and not saved_search.enabled:
        logger.error("The rule is not enabled on the platform")
        error = True
    elif is_disabled is None and saved_search.enabled:
        logger.info("The rule is enabled as expected")

    if error:
        return error


def integrity_rule_ms_xdr_mssp(rule_converted, rule_content, platform: MicrosoftXDRPlatform, rule_file, parameters, logger, error):

    try:
        export_list = platform.get_export_list_mssp()
    except Exception as e:
        logger.error(f"Couldn't get the export list for the designated customers - error {e}")
        return error

    logger.info("Integrity check for designated customers")

    error_occured = False

    for group, info in export_list.items():
        tenant_id = info['tenant_id']

        logger.debug(f"Processing rule on tenant {tenant_id} from group id {group}")
        try:
            saved_search: dict = platform.get_rule(rule_content["id"], tenant_id)
        except Exception as e:
            logger.error(f"Couldn't check the integrity for the rule {rule_file} on tenant {tenant_id} from {group} - error {e}")
            return error

        error = check_rule_removed(rule_content, rule_file, saved_search, logger, error)
        if error is not None:
            error_occured = True
            continue

        error = integrity_rule_ms_xdr(rule_converted, rule_content, platform, rule_file, parameters, logger, error, saved_search=saved_search)

        if error:
            error_occured = True

    if error_occured:
        return error

def integrity_rule_ms_xdr(rule_converted, rule_content, platform: MicrosoftXDRPlatform, rule_file, parameters, logger, error, saved_search=None):
    try:
        if not saved_search:
            saved_search: dict = platform.get_rule(rule_content["id"])
    except Exception as e:
        logger.error(f"Couldn't check the integrity for the rule {rule_file} - error {e}")
        return error

    error = check_rule_removed(rule_content, rule_file, saved_search, logger, error)
    if error is not None:
        return error

    logger.info(f"Successfully retrieved the rule {rule_file}")

    result = {
        "description": saved_search["detectionAction"]["alertTemplate"]["description"],
        "query": saved_search["queryCondition"]["queryText"]
    }

    rule_content["detection"] = rule_converted

    mapping = {
        "detection": "query",
        "description": "description"
    }
    for key in mapping:
        rule_key = key
        result_key = mapping[key]

        if rule_content.get(rule_key) == result.get(result_key):
            logger.debug(f"{rule_key} in rule_content matches {result_key} in result")
        else:
            logger.error(f"{rule_key} in rule_content does not match {result_key} in result")
            error = True

    # Check if disabled
    is_disabled = rule_content.get("custom", {}).get("disabled")

    if is_disabled and not saved_search["isEnabled"]:
        logger.info("The rule is disabled as expected")
    elif is_disabled and saved_search["isEnabled"]:
        logger.error("The rule is not disabled on the platform")
        error = True
    elif is_disabled is None and not saved_search["isEnabled"]:
        logger.error("The rule is not enabled on the platform")
        error = True
    elif is_disabled is None and saved_search["isEnabled"]:
        logger.info("The rule is enabled as expected")

    if error:
        return error


def integrity_rule_elastic(rule_converted, rule_content, platform: ElasticPlatform, rule_file, parameters, logger, error):
    try:
        saved_search: dict = platform.get_rule(rule_content["id"])
    except Exception as e:
        logger.error(f"Couldn't check the integrity for the rule {rule_file} - error {e}")
        return error

    error = check_rule_removed(rule_content, rule_file, saved_search, logger, error)
    if error is not None:
        return error

    logger.info(f"Successfully retrieved the rule {rule_file}")

    if "metadata _id, _index, _version" not in rule_converted.lower() and "metadata _id, _index, _version" in saved_search["query"].lower():
        saved_search["query"] = saved_search["query"].replace("  METADATA _id, _index, _version", "")

    result = {
        "name": saved_search["name"],
        "description": saved_search["description"],
        "query": saved_search["query"]
    }

    rule_content["detection"] = rule_converted

    mapping = {
        "detection": "query",
        "description": "description"
    }
    for key in mapping:
        rule_key = key
        result_key = mapping[key]

        if rule_content.get(rule_key) == result.get(result_key):
            logger.debug(f"{rule_key} in rule_content matches {result_key} in result")
        else:
            logger.error(f"{rule_key} in rule_content does not match {result_key} in result")
            error = True

    # Check if disabled
    if "custom" in rule_content and "disabled" in rule_content["custom"]:
        is_disabled = rule_content["custom"]["disabled"]
    else:
        is_disabled = False

    if is_disabled and not rule_content["enabled"]:
        logger.info("The rule is disabled as expected")
    elif is_disabled and rule_content["enabled"]:
        logger.error("The rule is not disabled on the platform")
        error = True
    elif is_disabled is None and not rule_content["enabled"]:
        logger.error("The rule is not enabled on the platform")
        error = True
    elif is_disabled is None and rule_content["enabled"]:
        logger.info("The rule is enabled as expected")

    if error:
        return error

def integrity_rule(parameters, rule_converted, rule_content, platform, rule_file, error, logger_param):

    logger = ColorLogger(__name__, **logger_param)

    error = False

    rule_content = post_rule_content(rule_content)

    if parameters.platform == "splunk":
        error = integrity_rule_splunk(rule_converted, rule_content, platform, rule_file, parameters, logger, error)
        return error
    elif parameters.platform in ["esql", "eql"]:
        error = integrity_rule_elastic(rule_converted, rule_content, platform, rule_file, parameters, logger, error)
        return error
    elif "microsoft_sentinel" in parameters.platform and parameters.mssp:
        error = integrity_rule_sentinel_mssp(rule_converted, rule_content, platform, rule_file, parameters, logger, error)
        return error
    elif "microsoft_sentinel" in parameters.platform:
        error = integrity_rule_sentinel(rule_converted, rule_content, platform, rule_file, parameters, logger, error)
        return error
    elif "microsoft_xdr" in parameters.platform and parameters.sentinel_xdr and parameters.mssp:
        error = integrity_rule_sentinel_mssp(rule_converted, rule_content, platform, rule_file, parameters, logger, error)
        return error
    elif "microsoft_xdr" in parameters.platform and parameters.sentinel_xdr:
        error = integrity_rule_sentinel(rule_converted, rule_content, platform, rule_file, parameters, logger, error)
        return error
    elif parameters.platform == "microsoft_xdr" and parameters.mssp:
        error = integrity_rule_ms_xdr_mssp(rule_converted, rule_content, platform, rule_file, parameters, logger, error)
        return error
    elif parameters.platform == "microsoft_xdr":
        error = integrity_rule_ms_xdr(rule_converted, rule_content, platform, rule_file, parameters, logger, error)
        return error

def integrity_rule_raw(parameters: dict, export_config: dict, logger_param: dict, raw_rule=False):

    error = False
    logger = ColorLogger(__name__, **logger_param)
    path = Path(parameters.rules)

    if parameters.platform == "splunk":
        platform = SplunkPlatform(export_config, logger_param)
    elif parameters.platform == "esql" or parameters.platform == "eql":
        platform = ElasticPlatform(export_config, logger_param, parameters.platform, raw=True)
    elif parameters.platform == "microsoft_sentinel" and parameters.mssp:
        platform = SentinelPlatform(export_config, logger_param, export_mssp=True)
    elif parameters.platform == "microsoft_sentinel":
        platform = SentinelPlatform(export_config, logger_param, export_mssp=False)
    elif "microsoft_xdr" in parameters.platform and parameters.sentinel_xdr and parameters.mssp:
        platform = SentinelPlatform(export_config, logger_param, export_mssp=True)
    elif "microsoft_xdr" in parameters.platform and parameters.sentinel_xdr:
        platform = SentinelPlatform(export_config, logger_param, export_mssp=False)
    elif parameters.platform == "microsoft_xdr" and parameters.mssp:
        platform = MicrosoftXDRPlatform(export_config, logger_param, export_mssp=True)
    elif parameters.platform == "microsoft_xdr":
        platform = MicrosoftXDRPlatform(export_config, logger_param, export_mssp=False)

    if path.is_dir():
        error_i = False
        for rule_file in path.rglob("*.y*ml"):
            rule_content = load_rule(rule_file)
            rule_converted = rule_content["detection"]
            error = integrity_rule(parameters, rule_converted, rule_content, platform, rule_file, error, logger_param)

            if error:
                custom_settings = rule_content.get("custom", {})
                if custom_settings.get("ignore_export_error", False):
                    logger.warning(f"(Ignoring) rule not found {rule_file}")
                elif custom_settings.get("removed", False):
                    logger.info(f"Rule not found and intended to be removed {rule_file}")
                else:
                    error_i = True

        return error_i


    elif path.is_file():
        rule_file = path
        rule_content = load_rule(rule_file)
        rule_converted = rule_content["detection"]
        error = integrity_rule(parameters, rule_converted, rule_content, platform, rule_file, error, logger_param)
        if error and rule_content.get("custom", {}).get("ignore_export_error", False):
            logger.warning(f"(Ignoring) rule not found {rule_file}")
            error = False
        elif error and rule_content.get("custom", {}).get("removed", False):
            logger.info(f"Rule not found and intended to be removed {rule_file}")
            error = False
    else:
        print(f"The path {path} is neither a directory nor a file.")

    return error