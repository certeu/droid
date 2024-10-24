"""
Module handling the searches in platform
"""
import yaml

from pathlib import Path
from droid.platforms.splunk import SplunkPlatform
from droid.platforms.sentinel import SentinelPlatform
from droid.platforms.elastic import ElasticPlatform
from droid.platforms.ms_xdr import MicrosoftXDRPlatform
from droid.color import ColorLogger

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

def search_rule_splunk(rule_converted, platform: SplunkPlatform, rule_file, parameters, logger, error, search_warning):
    try:
        result: dict = platform.run_splunk_search(rule_converted, rule_file)
        logger.info(f"Successfully searched the rule {rule_file}")

        if result["resultCount"] > 0: # If the rule has match
            job_url = result["jobUrl"]
            logger.warning(f"(Splunk) Match found for {rule_file} - {job_url}")
            search_warning = True
            return error, search_warning
        else:
            logger.info(f"(Splunk) No hits for {rule_file}")
            return error, search_warning

    except Exception as e:
        logger.error(f"Couldn't search for the rule {rule_file} - error {e}")
        error = True
        return error, search_warning

def search_rule_sentinel(rule_converted, platform: SentinelPlatform, rule_file, parameters, logger, error, search_warning, mssp_mode):

    try:
        result: int = platform.run_sentinel_search(rule_converted, rule_file, mssp_mode)

        logger.info(f"Successfully searched the rule {rule_file}")

        if result > 0: # If the rule has match
            logger.warning(f"(Sentinel) Match found for {rule_file}")
            search_warning = True
            return error, search_warning
        else:
            logger.info(f"(Sentinel) No hits for {rule_file}")
            return error, search_warning

    except Exception as e:
        logger.error(f"Couldn't search for the rule {rule_file} - error {e}")
        error = True
        return error, search_warning

def search_rule_ms_xdr_mssp(rule_converted, platform: MicrosoftXDRPlatform, rule_file, parameters, logger, error, search_warning):

    try:
        export_list = platform.get_export_list_mssp()
    except Exception as e:
        logger.error(f"Couldn't get the export list for the designated customers - error {e}")
        return error

    logger.info("Searching for designated customers")

    for group, info in export_list.items():

        tenant_id = info['tenant_id']

        logger.debug(f"Processing rule on {tenant_id} from group id {group}")

        try:
            result: int = platform.run_xdr_search(rule_converted, rule_file, tenant_id=tenant_id)

            logger.info(f"Successfully searched the rule {rule_file}")

            if result > 0:  # If the rule has a match
                logger.warning(f"{result} Matches found for {rule_file}")
                search_warning = True
            else:
                logger.info(f"No hits for {rule_file}")

        except Exception as e:
            logger.error(f"Couldn't search for the rule {rule_file} for tenant {tenant_id} - error {e}")
            error = True

    return error, search_warning

def search_rule_ms_xdr(rule_converted, platform: MicrosoftXDRPlatform, rule_file, parameters, logger, error, search_warning):

    try:
        result: int = platform.run_xdr_search(rule_converted, rule_file)

        logger.info(f"Successfully searched the rule {rule_file}")

        if result > 0: # If the rule has match
            logger.warning(f"{result} Matches found for {rule_file}")
            search_warning = True
            return error, search_warning
        else:
            logger.info(f"No hits for {rule_file}")
            return error, search_warning

    except Exception as e:
        logger.error(f"Couldn't search for the rule {rule_file} - error {e}")
        error = True
        return error, search_warning

def search_rule_elastic(rule_converted, platform: ElasticPlatform, rule_file, parameters, logger, error, search_warning, rule_content, platform_name):

    try:
        result: int = platform.run_elastic_search(rule_converted, platform_name, rule_content)

        logger.info(f"Successfully searched the rule {rule_file}")

        if result > 0: # If the rule has match
            logger.warning(f"(Elastic) {result} hits found for {rule_file}")
            search_warning = True
            return error, search_warning
        else:
            logger.info(f"(Elastic) No hits for {rule_file}")
            return error, search_warning

    except Exception as e:
        logger.error(f"Couldn't search for the rule {rule_file} - error {e}")
        error = True
        return error, search_warning

def search_rule(parameters, rule_content, rule_converted, platform, rule_file, error, search_warning, logger_param):

    logger = ColorLogger(__name__, **logger_param)

    error = False
    search_warning = False

    if rule_content.get("custom", {}).get("ignore_search", False):
        logger.warning(f"Search is ignored for {rule_file}")
        return error, search_warning

    if parameters.platform == "splunk":
        error, search_warning = search_rule_splunk(rule_converted, platform, rule_file, parameters, logger, error, search_warning)
        return error, search_warning
    elif parameters.platform in ["esql", "eql"]:
        error, search_warning = search_rule_elastic(rule_converted, platform, rule_file,
                                                    parameters, logger, error, search_warning,
                                                    rule_content, parameters.platform)
        return error, search_warning
    elif parameters.platform == "microsoft_sentinel" or (parameters.sentinel_xdr and parameters.platform == "microsoft_xdr"):
        if parameters.mssp:
            error, search_warning = search_rule_sentinel(rule_converted, platform, rule_file, parameters, logger, error, search_warning, mssp_mode=True)
            return error, search_warning
        else:
            error, search_warning = search_rule_sentinel(rule_converted, platform, rule_file, parameters, logger, error, search_warning, mssp_mode=False)
            return error, search_warning
    elif parameters.platform == "microsoft_xdr":
        if parameters.mssp:
            error, search_warning = search_rule_ms_xdr_mssp(rule_converted, platform, rule_file, parameters, logger, error, search_warning)
            return error, search_warning
        else:
            error, search_warning = search_rule_ms_xdr(rule_converted, platform, rule_file, parameters, logger, error, search_warning)
            return error, search_warning

def search_rule_raw(parameters: dict, export_config: dict, logger_param: dict):

    logger = ColorLogger(__name__, **logger_param)

    error = False
    search_warning = False

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
        search_warning_i = False
        for rule_file in path.rglob("*.y*ml"):
            rule_content = load_rule(rule_file)
            rule_converted = rule_content["detection"]
            error, search_warning = search_rule(parameters, rule_content, rule_converted, platform, rule_file, error, search_warning, logger_param)
            if error:
                error_i = True
            if search_warning:
                search_warning_i = True
        if error_i:
            error = True
            return error, search_warning
        if search_warning_i:
            search_warning = True
            return error, search_warning
    elif path.is_file():
        rule_file = path
        rule_content = load_rule(rule_file)
        rule_converted = rule_content["detection"]
        error, search_warning = search_rule(parameters, rule_content, rule_converted, platform, rule_file, error, search_warning, logger_param)
    else:
        print(f"The path {path} is neither a directory nor a file.")

    return error, search_warning