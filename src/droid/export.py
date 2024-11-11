"""
Module to export the rules
"""
import yaml

from os import environ
from pathlib import Path
from droid.platforms.splunk import SplunkPlatform
from droid.platforms.sentinel import SentinelPlatform
from droid.platforms.elastic import ElasticPlatform
from droid.platforms.ms_xdr import MicrosoftXDRPlatform
from droid.color import ColorLogger

def post_rule_content(rule_content):
    """Post-processing of rule content

    Return rule_content dict with post-processing
    """

    if environ.get("DROID_ENV_DEV") == "True":
        rule_content["title"] = "[DEV]" + " " + rule_content["title"]

    return rule_content

def load_rule(rule_file):

    with open(rule_file, "r") as stream:
        try:
            object = list(yaml.safe_load_all(stream))[0]
            if "fields" in object:
                object.pop("fields")
                # Here we remove the fields to avoid Sigma to arbitrary
                # convert the rule to {{ query }} | table field1,field2
            return object
        except yaml.YAMLError as exc:
            print(exc)
            print("Error reading {0}".format(rule_file))
            error = True
            return error

def export_rule(
        parameters: dict, rule_content: object, rule_converted: str,
        platform: object, rule_file: str, error: bool,
        logger_param: dict):

    logger = ColorLogger(__name__, **logger_param)

    rule_content = post_rule_content(rule_content)

    try:
        if rule_content.get("custom", {}).get("removed", False): # If rule is set as removed
            platform.remove_rule(rule_content, rule_converted, rule_file)
        else:
            platform.create_rule(rule_content, rule_converted, rule_file)
    except Exception as e:
        logger.error(f"Could not export the rule {rule_file}: {e}")
        error = True
        return error

    logger.info(f"Successfully exported the rule {rule_file}")
    return error

def export_rule_raw(parameters: dict, export_config: dict, logger_param: dict):

    logger = ColorLogger(__name__, **logger_param)

    path = Path(parameters.rules)

    error = False

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
            rule_content = post_rule_content(rule_content)
            rule_converted = rule_content["detection"]
            if rule_content.get("custom", {}).get("removed", False): # If rule is set as removed
                try:
                    platform.remove_rule(rule_content, rule_converted, rule_file)
                except:
                    logger.error(f"Error in removing search for rule {rule_file}")
                    error_i = True
            else:
                try:
                    platform.create_rule(rule_content, rule_converted, rule_file)
                except:
                    if rule_content.get("custom", {}).get("ignore_export_error", False):
                        logger.warning(f"(Ignoring) Error in creating search for rule {rule_file}")
                    else:
                        logger.error(f"Error in creating search for rule {rule_file}")
                        error_i = True
        if error_i:
            error = True
            return error

    elif path.is_file():
        rule_file = path
        rule_content = load_rule(rule_file)
        rule_content = post_rule_content(rule_content)
        rule_converted = rule_content["detection"]
        if rule_content.get("custom", {}).get("removed", False): # If rule is set as removed
            try:
                platform.remove_rule(rule_content, rule_converted, rule_file)
            except Exception as e:
                logger.error(f"Error in removing search for rule {rule_file} - error: {e}")
                error = True
        else:
            try:
                platform.create_rule(rule_content, rule_converted, rule_file)
            except Exception as e:
                if rule_content.get("custom", {}).get("ignore_export_error", False):
                    logger.warning(f"(Ignoring) Error in creating search for rule {rule_file} - error: {e}")
                    error = False
                else:
                    logger.error(f"Error in creating search for rule {rule_file} - error: {e}")
                    error = True
        if error:
            return error
    else:
        print(f"The path {path} is neither a directory nor a file.")