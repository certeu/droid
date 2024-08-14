"""
Main class
"""

import argparse
import logging
import tomllib
import sys

from os import environ
from os import path

from droid.validate import validate_rules
from droid.convert import convert_rules
from droid.sources.sigmahq import update_sigmahq_core
from droid.search import search_rule_raw
from droid.export import export_rule_raw
from droid.list import list_keys
from droid.integrity import integrity_rule_raw
from droid.color import ColorLogger

def init_argparse() -> argparse.ArgumentParser:
    """Initialise the argument parsers
    Creates an instance of `argparse.ArgumentParser` and configures it
    with the DROID arguments.

    Returns:
        An instance of `argparse.ArgumentParser` configured with the specified
        command line arguments.
    """
    parser = argparse.ArgumentParser(
                        prog='droid',
                        description='Detection Rules Optimisation Integration Deployment',
                        )
    parser.add_argument("-v", "--validate", help="Validate the rules", action="store_true")
    parser.add_argument("-r", "--rules", help="Rules path", required=True)
    parser.add_argument("-s", "--search", help="Search in the platform using the rules", action="store_true")
    parser.add_argument("-c", "--convert", help="Convert the rules", action="store_true")
    parser.add_argument("-cf", "--config-file", help="DROID configuration file path")
    parser.add_argument("-d", "--debug", help="Enable debugging", action="store_true")
    parser.add_argument("-e", "--export", help="Export the rules", action="store_true")
    parser.add_argument("-p", "--platform", help="Platform target", choices=['splunk', 'azure', 'microsoft_defender'])
    parser.add_argument("-sm", "--sentinel-mde", help="Use Sentinel as backend for MDE", action="store_true")
    parser.add_argument("-u", "--update", help="Update from source", choices=['sigmahq-core'])
    parser.add_argument("-l", "--list", help="List items from rules", choices=['unique_fields', 'pipelines'])
    parser.add_argument("-m", "--mssp", help="Enable MSSP mode", action="store_true")
    parser.add_argument("-mo", "--module", help="Module mode to return converted rules as a list", action="store_true")
    parser.add_argument("-j", "--json", help="Drop a JSON log file", action="store_true")
    parser.add_argument("-i", "--integrity", help="Perform an integrity check on platforms", action="store_true")
    return parser

def droid_base_config(args, config_path):
    """Base config
    Load all the objects within the [base] section in the DROID configuration file.

    Returns:
        a dictionary with the configuration file
    """
    try:
        with open(config_path) as file_obj:
            content = file_obj.read()
            config_data = tomllib.loads(content)
            config = config_data["base"]
    except Exception as e:
        raise Exception(f"Something unexepected happened: {e}")

    return config

def is_raw_rule(args, base_config):
    """Verify rule type
    Check if a rule is "raw" by looking for a match with raw_rule_folder_name and the rule path (-r)

    Returns:
        - True if it's a raw rule
        - False if it's a Sigma rule
    """
    if "raw_rules_directory" in base_config:
        try:
            raw_rule_folder_name = base_config["raw_rules_directory"]
        except Exception as e:
            print(f"Could not read the key raw_rule_folder_name from the DROID configuration: {e}")
            exit(1)
    else:
        return False

    if (
        (args.platform in ['splunk', 'azure'] or
        (args.platform == 'microsoft_defender' and args.sentinel_mde)) and
        (raw_rule_folder_name in args.rules and args.platform in args.rules)
    ):
        return True

    elif (
        args.platform in ['splunk', 'azure'] or
        (args.platform == 'microsoft_defender' and args.sentinel_mde)
    ):
        return False

    elif (
        (raw_rule_folder_name in args.rules) and
        (args.validate or args.convert)
    ):
        return True

    elif (
        (raw_rule_folder_name not in args.rules) and
        (args.validate or args.convert)
    ):
        return False

    else:
        print("Please select a platform.")
        exit(1)


def droid_platform_config(args, config_path):
    """Platform configuration
    Loads the configuration based on the supported platform specified in the DROID configuration file [platforms.foo].

    Returns:
        a dictionary with the platform configuration file
    """
    if (args.convert or args.export) and not args.platform:
        exit("Please select one target platform. Use --help")

    if args.platform == 'splunk':
        try:
            with open(config_path) as file_obj:
                content = file_obj.read()
                config_data = tomllib.loads(content)
                config_splunk = config_data["platforms"]["splunk"]
        except Exception as e:
            raise Exception(f"Something unexepected happened: {e}")

        if args.export or args.search or args.integrity:
            if environ.get('DROID_SPLUNK_USER'):
                splunk_user = environ.get('DROID_SPLUNK_USER')
                config_splunk["user"] = splunk_user
            else:
                raise Exception("Please use: export DROID_SPLUNK_USER=<user>")

            if environ.get('DROID_SPLUNK_PASSWORD'):
                splunk_password = environ.get('DROID_SPLUNK_PASSWORD')
                config_splunk["password"] = splunk_password
            else:
                raise Exception("Please use: export DROID_SPLUNK_PASSWORD=<password>")
            # Replace Splunk url if env available
            if environ.get('DROID_SPLUNK_URL'):
                config_splunk['url'] = environ.get('DROID_SPLUNK_URL')
            # Replace Splunk webhook url if env available
            if environ.get('DROID_SPLUNK_WEBHOOK_URL'):
                config_splunk['action']['action.webhook.param.url'] = environ.get('DROID_SPLUNK_WEBHOOK_URL')

        return config_splunk

    if 'azure' or 'defender' in args.platform:

        try:
            with open(config_path) as file_obj:
                content = file_obj.read()
                config_data = tomllib.loads(content)
                if args.platform == 'microsoft_defender' and args.sentinel_mde:
                    # With Azure Sentinel as backend, loads config from azure but keep MDE pipelines
                    config = config_data["platforms"]["azure"]
                    config["pipelines"] = config_data["platforms"]["microsoft_defender"]["pipelines"]
                else:
                    config = config_data["platforms"][args.platform]
                # Replace workspace id and workspace name if env available
                if environ.get('DROID_AZURE_WORKSPACE_ID'):
                    config['workspace_id'] = environ.get('DROID_AZURE_WORKSPACE_ID')
                if environ.get('DROID_AZURE_WORKSPACE_NAME'):
                    config['workspace_name'] = environ.get('DROID_AZURE_WORKSPACE_NAME')
        except Exception:
            raise Exception("Something unexepected happened...")

        if args.export or args.search:

            if  (
                    args.platform == 'microsoft_defender' and
                    config["search_auth"] != "app" and
                    config["export_auth"] != "app" and not
                    args.sentinel_mde
                ):
                    exit("Error: DROID only supports Azure App Registration authentication method for MDE.")

            if config["search_auth"] == "app":

                if environ.get('DROID_AZURE_TENANT_ID'):
                    tenant_id = environ.get('DROID_AZURE_TENANT_ID')
                    config["tenant_id"] = tenant_id
                else:
                    raise Exception("Please use: export DROID_AZURE_TENANT_ID=<tenant_id>")

                if environ.get('DROID_AZURE_CLIENT_ID'):
                    client_id = environ.get('DROID_AZURE_CLIENT_ID')
                    config["client_id"] = client_id
                else:
                    raise Exception("Please use: export DROID_AZURE_CLIENT_ID=<client_id>")

                if environ.get('DROID_AZURE_CLIENT_SECRET'):
                    client_secret = environ.get('DROID_AZURE_CLIENT_SECRET')
                    config["client_secret"] = client_secret
                else:
                    raise Exception("Please use: export DROID_AZURE_CLIENT_SECRET=<client_secret>")

            elif config["export_auth"] == "app" and args.export:

                if environ.get('DROID_AZURE_TENANT_ID'):
                    tenant_id = environ.get('DROID_AZURE_TENANT_ID')
                    config["tenant_id"] = tenant_id
                else:
                    raise Exception("Please use: export DROID_AZURE_TENANT_ID=<tenant_id>")

                if environ.get('DROID_AZURE_CLIENT_ID'):
                    client_id = environ.get('DROID_AZURE_CLIENT_ID')
                    config["client_id"] = client_id
                else:
                    raise Exception("Please use: export DROID_AZURE_CLIENT_ID=<client_id>")

                if environ.get('DROID_AZURE_CLIENT_SECRET'):
                    client_secret = environ.get('DROID_AZURE_CLIENT_SECRET')
                    config["client_secret"] = client_secret
                else:
                    raise Exception("Please use: export DROID_AZURE_CLIENT_SECRET=<client_secret>")

        return config

def main(argv=None) -> None:
    """Main function

    This function simply execute what's provided in args
    """
    parser = init_argparse()
    args = parser.parse_args(argv)

    logger = ColorLogger("droid")

    # Set logger level based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Configure JSON logging if requested
    if args.json:
        logger.enable_json_logging()

    logging.setLoggerClass(ColorLogger)

    parameters = args

    if (args.platform or args.update or args.validate) and not args.config_file:
        raise Exception("Please provide a configuration file using -cf/--config-file.")
    elif args.platform and not path.isfile(args.config_file):
        raise Exception(f"Error: configuration file {args.config_file} not found.")
    else:
        config_path = args.config_file

    if args.validate:

        logger.info(f"Validation mode was selected - path selected: {args.rules}")

        base_config = droid_base_config(args, config_path)

        if is_raw_rule(args, base_config):
            logger.info("Raw rules are not subject to Sigma validation.")
            exit(0)

        rule_error = validate_rules(parameters, False, base_config)

        if rule_error:
            logger.error("Validation issues found")
            exit(1)
        else:
            logger.info("No validation issues found")
            exit(0)

    if args.convert:

        logger.info(f"Convert mode was selected - path selected: {args.rules}")

        base_config = droid_base_config(args, config_path)

        if is_raw_rule(args, base_config):
            logger.info("Raw rules are not subject to Sigma conversion.")
            exit(0)

        if not args.platform:
            logger.error("Please select a platform.")
            exit(1)

        conversion_error, search_warning = convert_rules(parameters, droid_platform_config(args, config_path), base_config)

        if conversion_error:
            logger.error("Conversion errors found")
            exit(1)
        else:
            logger.info("Successfully converted the rules")
            exit(0)

    if args.search:

        logger.info(f"Search mode was selected - path selected: {args.rules}")

        base_config = droid_base_config(args, config_path)

        if is_raw_rule(args, base_config):
            logger.info(f"Searching raw rule for platform {args.platform} selected")
            search_error, search_warning = search_rule_raw(parameters, droid_platform_config(args, config_path))
        else:
            logger.info(f"Searching Sigma rule for platform {args.platform} selected")
            search_error, search_warning = convert_rules(parameters, droid_platform_config(args, config_path))

        if search_error and search_warning:
            logger.warning("Hits found while search one or multiple rules")
            logger.error("Error in searching the rules")
            exit(1)
        if search_error:
            logger.error("Error in searching the rules")
            exit(1)
        elif search_warning:
            logger.warning("Hits found while search one or multiple rules")
            exit(66)
        elif args.export:
            logger.info("Successfully searched and exported the rules")
            exit(0)
        else:
            logger.info("Successfully searched the rules")
            exit(0)

    elif args.export:
        logger.info(f"Export mode was selected - path selected: {args.rules}")

        base_config = droid_base_config(args, config_path)

        if args.platform == 'splunk':
            if is_raw_rule(args, base_config):
                logger.info("Splunk raw rule selected")
                export_error = export_rule_raw(parameters, droid_platform_config(args, config_path))
            else:
                export_error = convert_rules(parameters, droid_platform_config(args, config_path))

        elif args.platform == 'azure':
            if is_raw_rule(args, base_config):
                logger.info("Azure Sentinel raw rule selected")
                export_error = export_rule_raw(parameters, droid_platform_config(args, config_path))
            else:
                export_error = convert_rules(parameters, droid_platform_config(args, config_path))

        elif args.platform == 'microsoft_defender' and args.sentinel_mde:
            if is_raw_rule(args, base_config):
                logger.info("Microsoft Defender for Endpoint raw rule selected")
                export_error = export_rule_raw(parameters, droid_platform_config(args, config_path))
            else:
                export_error = convert_rules(parameters, droid_platform_config(args, config_path))

        elif args.platform == "microsoft_defender" and not args.sentinel_mde:
            logger.error("Export mode for MDE is only avalailable via Azure Sentinel backend for now.")
            exit(1)

        else:
            logger.error("Please select one platform. See option -p in --help")
            exit(1)

        if export_error:
            logger.error("Error in exporting the rules")
        else:
            logger.info("Successfully exported the rules")

    elif args.update:

        logger.info(f"Update mode was selected for source {args.update} - source selected: {args.rules}")

        if parameters.update == 'sigmahq-core':
            update_sigmahq_core(parameters)

    elif args.list:

        logger.info(f"List mode was selected - path selected: {args.rules}")
        list_keys_errors = list_keys(parameters)

    elif args.integrity:

        logger.info(f"Integrity check mode was selected - path selected: {args.rules}")

        base_config = droid_base_config(args, config_path)

        if is_raw_rule(args, base_config):
            logger.info(f"Integrity check for platform {args.platform} selected")
            integrity_error = integrity_rule_raw(parameters, droid_platform_config(args, config_path))
        else:
            logger.info(f"Integrity check for platform {args.platform} selected")
            integrity_error = convert_rules(parameters, droid_platform_config(args, config_path))

        if integrity_error:
            logger.error("Integrity error")
            exit(1)
        else:
            logger.info("Integrity check successful")
            exit(0)

if __name__ == "__main__":
    sys.exit(main())