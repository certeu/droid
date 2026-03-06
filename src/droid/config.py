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
    from droid.platforms.registry import PLATFORM_REGISTRY

    if "raw_rules_directory" not in base_config:
        return False

    raw_dir = base_config["raw_rules_directory"]
    platform_name = parameters.platform

    if platform_name not in PLATFORM_REGISTRY:
        # No platform selected — validate/convert mode
        if raw_dir in parameters.rules and (
            getattr(parameters, "validate", False) or getattr(parameters, "convert", False)
        ):
            return True
        if raw_dir not in parameters.rules and (
            getattr(parameters, "validate", False) or getattr(parameters, "convert", False)
        ):
            return False
        print("Please select a platform.")
        exit(1)

    strategy = PLATFORM_REGISTRY[platform_name].raw_rule_strategy
    if strategy.never_raw:
        return False
    if raw_dir not in parameters.rules:
        return False
    if strategy.require_platform_in_path:
        return platform_name in parameters.rules
    return True


def load_platform_config(parameters, config_path: str) -> dict:
    """Load the platform-specific configuration section.

    Driven by the platform descriptor registry — no per-platform branching.
    """
    from droid.platforms.registry import PLATFORM_REGISTRY

    if (getattr(parameters, "convert", False) or getattr(parameters, "export", False)) and not parameters.platform:
        exit("Please select one target platform. Use --help")

    platform_name = parameters.platform
    if platform_name not in PLATFORM_REGISTRY:
        return {}

    descriptor = PLATFORM_REGISTRY[platform_name]

    try:
        with open(config_path) as fh:
            full_toml = tomllib.loads(fh.read())
    except Exception as e:
        raise Exception(f"Could not load config file: {e}")

    toml_key = descriptor.resolve_toml_key(parameters)
    try:
        config = full_toml["platforms"][toml_key]
    except KeyError:
        raise Exception(f"Missing [platforms.{toml_key}] section in config file")

    if descriptor.post_load_transform:
        config = descriptor.post_load_transform(config, full_toml, parameters)

    for group in descriptor.env_var_groups:
        if group.condition is not None and not group.condition(config, parameters):
            continue
        for mapping in group.mappings:
            value = environ.get(mapping.env_var)
            if value:
                if mapping.nested_key:
                    config.setdefault(mapping.nested_key, {})[mapping.config_key] = value
                else:
                    config[mapping.config_key] = value
            elif mapping.required:
                raise Exception(f"Please use: export {mapping.env_var}=<value>")
            elif mapping.default is not None:
                config[mapping.config_key] = mapping.default

    if descriptor.post_load_validator:
        descriptor.post_load_validator(config, parameters)

    return config
