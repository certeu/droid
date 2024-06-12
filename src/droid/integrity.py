"""
Module handling the integrity check of the rules on the platforms.
"""
import yaml

from pathlib import Path
from droid.platforms.splunk import SplunkPlatform
from droid.platforms.sentinel import SentinelPlatform
from droid.color import ColorLogger
from droid.export import post_rule_content

def load_rule(rule_file):

    with open(rule_file, 'r') as stream:
        try:
            object = list(yaml.safe_load_all(stream))[0]
            return object
        except yaml.YAMLError as exc:
            print(exc)
            print("Error reading {0}".format(rule_file))
            error = True
            return error

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

    if saved_search:
        logger.info(f"Successfully retrieved the rule {rule_file}")
    else:
        logger.error(f"Rule not found {rule_file}")
        error = True
        return error

    result = {
        "description": saved_search['description'],
        "search": saved_search['search']
    }

    rule_content["detection"] = rule_converted

    for key in mapping:

        rule_key = key
        result_key = mapping[key]

        if rule_content.get(rule_key) == result.get(result_key):
            if parameters.debug:
                logger.debug(f"{rule_key} in rule_content matches {result_key} in result")
        else:
            logger.error(f"{rule_key} in rule_content does not match {result_key} in result")
            error = True

    # Check if disabled
    is_disabled = rule_content.get('custom', {}).get('disabled')

    if saved_search['disabled'] == "0":
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

def integrity_rule_sentinel(rule_converted, rule_content, platform: SentinelPlatform, rule_file, parameters, logger, error):

    try:
        saved_search: dict = platform.get_search(rule_content, rule_file)
    # Mapping rule_content with a MS Sentinel saved search properties
        mapping = {
            "id": "name",
            "detection": "query",
            "description": "description"
        }
    except Exception as e:
        logger.error(f"Couldn't check the integrity for the rule {rule_file} - error {e}")
        return error

    if saved_search:
        logger.info(f"Successfully retrieved the rule {rule_file}")
    else:
        logger.error(f"Rule not found {rule_file}")
        error = True
        return error

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
            if parameters.debug:
                logger.debug(f"{rule_key} in rule_content matches {result_key} in result")
        else:
            logger.error(f"{rule_key} in rule_content does not match {result_key} in result")
            error = True

    # Check if disabled
    is_disabled = rule_content.get('custom', {}).get('disabled')

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

def integrity_rule(parameters, rule_converted, rule_content, platform, rule_file, error):

    logger = ColorLogger("droid.integrity")

    error = False

    rule_content = post_rule_content(rule_content)

    if parameters.json:
        logger.enable_json_logging()

    if parameters.platform == 'splunk':
        error = integrity_rule_splunk(rule_converted, rule_content, platform, rule_file, parameters, logger, error)
        return error

    elif 'azure' or 'defender' in parameters.platform:
        error = integrity_rule_sentinel(rule_converted, rule_content, platform, rule_file, parameters, logger, error)
        return error

def integrity_rule_raw(parameters: dict, export_config: dict, raw_rule=False):

    error = False

    path = Path(parameters.rules)

    if parameters.platform == 'splunk':
        platform = SplunkPlatform(export_config, parameters.debug, parameters.json)
    elif parameters.platform == 'azure':
        platform = SentinelPlatform(export_config, parameters.debug, parameters.json)
    elif parameters.platform == 'microsoft_defender' and parameters.sentinel_mde:
        platform = SentinelPlatform(export_config, parameters.debug, parameters.json)

    if path.is_dir():
        error_i = False
        for rule_file in path.rglob("*.y*ml"):
            rule_content = load_rule(rule_file)
            rule_converted = rule_content['detection']
            error = integrity_rule(parameters, rule_converted, rule_content, platform, rule_file, error)
            if error:
                error_i = True
        if error_i:
            error = True
            return error

    elif path.is_file():
        rule_file = path
        rule_content = load_rule(rule_file)
        rule_converted = rule_content['detection']
        error = integrity_rule(parameters, rule_converted, rule_content, platform, rule_file, error)
    else:
        print(f"The path {path} is neither a directory nor a file.")

    return error