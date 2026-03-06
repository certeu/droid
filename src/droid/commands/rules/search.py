"""Search command – search platforms using the detection rules."""

import typer
from typing import Optional

from droid.registry import register_command
from droid.config import (
    Platform,
    build_logger_param,
    build_parameters,
    get_global_opts,
    init_logger,
    is_raw_rule,
    load_base_config,
    load_platform_config,
)
from droid.convert import convert_rules
from droid.search import search_rule_raw


@register_command("rules", "search")
def search(
    ctx: typer.Context,
    rules: str = typer.Option(..., "--rules", "-r", help="Rules path"),
    config_file: str = typer.Option(..., "--config-file", "-c", help="DROID configuration file path"),
    platform: Platform = typer.Option(..., "--platform", "-p", help="Platform target"),
    mssp: bool = typer.Option(False, "--mssp", "-m", help="Enable MSSP mode"),
    sentinel_xdr: bool = typer.Option(
        False, "--sentinel-xdr",
        help="Use Microsoft Sentinel as search head for Microsoft XDR",
    ),
) -> None:
    """Search in the platform using the detection rules."""
    debug, json_log, json_stdout, json_output = get_global_opts(ctx)
    logger_param = build_logger_param(debug, json_log, json_stdout, json_output)
    logger = init_logger(logger_param)

    params = build_parameters(
        rules=rules,
        config_file=config_file,
        platform=platform.value,
        search=True,
        mssp=mssp,
        sentinel_xdr=sentinel_xdr,
        debug=debug,
        json=json_log,
        json_output=json_output,
        json_stdout=json_stdout,
    )

    logger.info(f"Search mode was selected - path selected: {rules}")

    base_config = load_base_config(config_file)
    platform_config = load_platform_config(params, config_file)

    if is_raw_rule(params, base_config):
        logger.info(f"Searching raw rule for platform {platform.value} selected")
        search_error, search_warning = search_rule_raw(params, platform_config, logger_param)
    else:
        logger.info(f"Searching Sigma rule for platform {platform.value} selected")
        search_error, search_warning = convert_rules(params, platform_config, base_config, logger_param)

    if search_error and search_warning:
        logger.warning("Hits found while searching one or multiple rules")
        logger.error("Error in searching the rules")
        raise typer.Exit(code=1)
    if search_error:
        logger.error("Error in searching the rules")
        raise typer.Exit(code=1)
    elif search_warning:
        logger.warning("Hits found while searching one or multiple rules")
        raise typer.Exit(code=66)
    else:
        logger.info("Successfully searched the rules")
        raise typer.Exit(code=0)
