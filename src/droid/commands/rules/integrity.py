"""Integrity command – perform an integrity check on platform rules."""

import typer

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
from droid.integrity import integrity_rule_raw


@register_command("rules", "integrity")
def integrity(
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
    """Perform an integrity check between local rules and the platform."""
    debug, json_log, json_stdout, json_output = get_global_opts(ctx)
    logger_param = build_logger_param(debug, json_log, json_stdout, json_output)
    logger = init_logger(logger_param)

    params = build_parameters(
        rules=rules,
        config_file=config_file,
        platform=platform.value,
        integrity=True,
        mssp=mssp,
        sentinel_xdr=sentinel_xdr,
        debug=debug,
        json=json_log,
        json_output=json_output,
        json_stdout=json_stdout,
    )

    logger.info(f"Integrity check mode was selected - path selected: {rules}")

    base_config = load_base_config(config_file)
    platform_config = load_platform_config(params, config_file)

    if is_raw_rule(params, base_config):
        logger.info(f"Integrity check for platform {platform.value} selected")
        integrity_error = integrity_rule_raw(params, platform_config, logger_param)
    else:
        logger.info(f"Integrity check for platform {platform.value} selected")
        integrity_error = convert_rules(params, platform_config, base_config, logger_param)

    if integrity_error:
        logger.error("Integrity error")
        raise typer.Exit(code=1)
    else:
        logger.info("Integrity check successful")
        raise typer.Exit(code=0)
