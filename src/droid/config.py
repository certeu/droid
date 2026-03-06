"""Shared configuration helpers for the droid CLI.

Centralises config loading, parameter building, platform config and
the raw rules check that were previously inlined in main.
"""

import logging
import tomllib

from enum import Enum
from os import environ
from types import SimpleNamespace
from typing import Optional

from droid.color import ColorLogger


# ---------------------------------------------------------------------------
# Enums used by Typer for argument validation
# ---------------------------------------------------------------------------

class Platform(str, Enum):
    splunk = "splunk"
    microsoft_sentinel = "microsoft_sentinel"
    microsoft_xdr = "microsoft_xdr"
    esql = "esql"
    eql = "eql"


class UpdateSource(str, Enum):
    sigmahq_core = "sigmahq-core"


class ListItem(str, Enum):
    unique_fields = "unique_fields"
    pipelines = "pipelines"
    validators = "validators"


# ---------------------------------------------------------------------------
# Parameter / logger helpers
# ---------------------------------------------------------------------------

def build_parameters(
    rules: str,
    platform: Optional[str] = None,
    config_file: Optional[str] = None,
    validate: bool = False,
    convert: bool = False,
    search: bool = False,
    export: bool = False,
    integrity: bool = False,
    update: Optional[str] = None,
    list: Optional[str] = None,
    debug: bool = False,
    json: bool = False,
    json_output: Optional[str] = None,
    json_stdout: bool = False,
    mssp: bool = False,
    sentinel_xdr: bool = False,
    module: bool = False,
) -> SimpleNamespace:
    """Build a ``SimpleNamespace`` compatible with the existing business-logic code."""
    return SimpleNamespace(
        rules=rules,
        platform=platform,
        config_file=config_file,
        validate=validate,
        convert=convert,
        search=search,
        export=export,
        integrity=integrity,
        update=update,
        list=list,
        debug=debug,
        json=json,
        json_output=json_output,
        json_stdout=json_stdout,
        mssp=mssp,
        sentinel_xdr=sentinel_xdr,
        module=module,
    )


def build_logger_param(
    debug: bool = False,
    json_log: bool = False,
    json_stdout: bool = False,
    json_output: Optional[str] = None,
) -> dict:
    """Return the logger-parameter dict expected by ``ColorLogger``."""
    return {
        "debug_mode": debug,
        "json_enabled": json_log,
        "json_stdout": json_stdout,
        "log_file": json_output,
    }


def init_logger(logger_param: dict) -> ColorLogger:
    """Initialise the root droid logger."""
    logger = ColorLogger("droid", **logger_param)
    if logger_param["debug_mode"]:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    logging.setLoggerClass(ColorLogger)
    return logger


def get_global_opts(ctx) -> tuple[bool, bool, bool, Optional[str]]:
    """Extract global options stored on the Typer ``Context``.

    Walks up the context chain to the root so this works with nested
    sub-apps (group commands).
    """
    current = ctx
    while current.parent is not None:
        current = current.parent
    obj = current.ensure_object(dict)
    return (
        obj.get("debug", False),
        obj.get("json", False),
        obj.get("json_stdout", False),
        obj.get("json_output"),
    )


# ---------------------------------------------------------------------------
# Config file loaders
# ---------------------------------------------------------------------------

def load_base_config(config_path: str) -> dict:
    """Load the ``[base]`` section from the DROID configuration file."""
    try:
        with open(config_path) as file_obj:
            content = file_obj.read()
            config_data = tomllib.loads(content)
            return config_data["base"]
    except Exception as e:
        raise Exception(f"Something unexpected happened: {e}")


def is_raw_rule(parameters, base_config: dict) -> bool:
    """Return *True* when the rule path points to raw (non-Sigma) rules."""
    if "raw_rules_directory" not in base_config:
        return False

    try:
        raw_rule_folder_name = base_config["raw_rules_directory"]
    except Exception as e:
        print(f"Could not read the key raw_rule_folder_name from the DROID configuration: {e}")
        exit(1)

    platform = parameters.platform

    if (
        platform in ["splunk", "microsoft_sentinel"]
        and raw_rule_folder_name in parameters.rules
        and platform in parameters.rules
    ):
        return True
    elif platform in ["esql", "eql"] and raw_rule_folder_name in parameters.rules:
        return True
    elif platform in ["esql", "eql"]:
        return False
    elif platform == "microsoft_xdr" and raw_rule_folder_name in parameters.rules:
        return True
    elif platform in ["splunk", "microsoft_sentinel"] or platform == "microsoft_xdr":
        return False
    elif raw_rule_folder_name in parameters.rules and (
        getattr(parameters, "validate", False) or getattr(parameters, "convert", False)
    ):
        return True
    elif raw_rule_folder_name not in parameters.rules and (
        getattr(parameters, "validate", False) or getattr(parameters, "convert", False)
    ):
        return False
    else:
        print("Please select a platform.")
        exit(1)


def load_platform_config(parameters, config_path: str) -> dict:
    """Load the platform-specific configuration section.

    Port of the original ``droid_platform_config`` from ``__main__``.
    """
    if (getattr(parameters, "convert", False) or getattr(parameters, "export", False)) and not parameters.platform:
        exit("Please select one target platform. Use --help")

    if parameters.platform == "splunk":
        try:
            with open(config_path) as file_obj:
                content = file_obj.read()
                config_data = tomllib.loads(content)
                config_splunk = config_data["platforms"]["splunk"]
        except Exception as e:
            raise Exception(f"Something unexpected happened: {e}")

        if getattr(parameters, "export", False) or getattr(parameters, "search", False) or getattr(parameters, "integrity", False):
            if environ.get("DROID_SPLUNK_USER"):
                config_splunk["user"] = environ.get("DROID_SPLUNK_USER")
            else:
                raise Exception("Please use: export DROID_SPLUNK_USER=<user>")

            if environ.get("DROID_SPLUNK_PASSWORD"):
                config_splunk["password"] = environ.get("DROID_SPLUNK_PASSWORD")
            else:
                raise Exception("Please use: export DROID_SPLUNK_PASSWORD=<password>")

            if environ.get("DROID_SPLUNK_URL"):
                config_splunk["url"] = environ.get("DROID_SPLUNK_URL")

            if environ.get("DROID_SPLUNK_WEBHOOK_URL"):
                config_splunk["action"]["action.webhook.param.url"] = environ.get("DROID_SPLUNK_WEBHOOK_URL")

        return config_splunk

    if parameters.platform in ("microsoft_sentinel", "microsoft_xdr"):
        try:
            with open(config_path) as file_obj:
                content = file_obj.read()
                config_data = tomllib.loads(content)
                if parameters.platform == "microsoft_xdr" and getattr(parameters, "sentinel_xdr", False):
                    config = config_data["platforms"]["microsoft_sentinel"]
                    config["pipelines"] = config_data["platforms"]["microsoft_xdr"]["pipelines"]
                else:
                    config = config_data["platforms"][parameters.platform]

                if environ.get("DROID_AZURE_WORKSPACE_ID"):
                    config["workspace_id"] = environ.get("DROID_AZURE_WORKSPACE_ID")
                if environ.get("DROID_AZURE_WORKSPACE_NAME"):
                    config["workspace_name"] = environ.get("DROID_AZURE_WORKSPACE_NAME")
                if environ.get("DROID_AZURE_SUBSCRIPTION_ID"):
                    config["subscription_id"] = environ.get("DROID_AZURE_SUBSCRIPTION_ID")
                if environ.get("DROID_AZURE_RESOURCE_GROUP"):
                    config["resource_group"] = environ.get("DROID_AZURE_RESOURCE_GROUP")
        except Exception:
            raise Exception("Something unexpected happened...")

        if getattr(parameters, "export", False) or getattr(parameters, "search", False) or getattr(parameters, "integrity", False):
            auth_methods = ["default", "app"]

            if environ.get("DROID_AZURE_SEARCH_AUTH"):
                config["search_auth"] = environ.get("DROID_AZURE_SEARCH_AUTH")

            if environ.get("DROID_AZURE_EXPORT_AUTH"):
                config["export_auth"] = environ.get("DROID_AZURE_EXPORT_AUTH")

            if "search_auth" in config and config["search_auth"] not in auth_methods:
                raise ValueError(f"Invalid search_auth: {config['search_auth']}")

            if "export_auth" in config and config["export_auth"] not in auth_methods:
                raise ValueError(f"Invalid export_auth: {config['export_auth']}")

            if (
                config["search_auth"] == "app" and "credential_file" not in config
            ) or (
                config["export_auth"] == "app"
                and getattr(parameters, "export", False)
                and "credential_file" not in config
            ):
                if environ.get("DROID_AZURE_TENANT_ID"):
                    config["tenant_id"] = environ.get("DROID_AZURE_TENANT_ID")
                else:
                    raise Exception("Please use: export DROID_AZURE_TENANT_ID=<tenant_id>")

                if environ.get("DROID_AZURE_CLIENT_ID"):
                    config["client_id"] = environ.get("DROID_AZURE_CLIENT_ID")
                else:
                    raise Exception("Please use: export DROID_AZURE_CLIENT_ID=<client_id>")

                if environ.get("DROID_AZURE_CLIENT_SECRET"):
                    config["client_secret"] = environ.get("DROID_AZURE_CLIENT_SECRET")
                else:
                    raise Exception("Please use: export DROID_AZURE_CLIENT_SECRET=<client_secret>")

                if environ.get("DROID_AZURE_CERT_PASS"):
                    config["cert_pass"] = environ.get("DROID_AZURE_CERT_PASS")
                else:
                    config["cert_pass"] = None

        return config

    if parameters.platform in ("esql", "eql"):
        try:
            with open(config_path) as file_obj:
                content = file_obj.read()
                config_data = tomllib.loads(content)
                config_elastic = config_data["platforms"]["elastic"]
        except Exception as e:
            raise Exception(f"Something unexpected happened: {e}")

        if config_elastic["auth_method"] == "basic":
            if getattr(parameters, "export", False) or getattr(parameters, "search", False) or getattr(parameters, "integrity", False):
                if environ.get("DROID_ELASTIC_USERNAME"):
                    config_elastic["username"] = environ.get("DROID_ELASTIC_USERNAME")
                else:
                    raise Exception("Please use: export DROID_ELASTIC_USERNAME=<username>")
                if environ.get("DROID_ELASTIC_PASSWORD"):
                    config_elastic["password"] = environ.get("DROID_ELASTIC_PASSWORD")
                else:
                    raise Exception("Please use: export DROID_ELASTIC_PASSWORD=<password>")

        return config_elastic

    return {}
