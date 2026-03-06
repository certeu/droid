"""Convert command – convert Sigma rules to platform query language."""

import typer
from rich import print

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


@register_command("rules", "convert")
def convert(
    ctx: typer.Context,
    rules: str = typer.Option(..., "--rules", "-r", help="Rules path"),
    config_file: str = typer.Option(..., "--config-file", "-c", help="DROID configuration file path"),
    platform: Platform = typer.Option(..., "--platform", "-p", help="Platform target"),
    mssp: bool = typer.Option(False, "--mssp", "-m", help="Enable MSSP mode"),
    sentinel_xdr: bool = typer.Option(
        False, "--sentinel-xdr", "-s",
        help="Use Microsoft Sentinel as search head for Microsoft XDR",
    ),
    module: bool = typer.Option(False, "--module", "-M", help="Module mode – return converted rules as a list"),
) -> None:
    """Convert the Sigma detection rules to the target platform query language."""
    debug, json_log, json_stdout, json_output = get_global_opts(ctx)
    logger_param = build_logger_param(debug, json_log, json_stdout, json_output)
    logger = init_logger(logger_param)

    params = build_parameters(
        rules=rules,
        config_file=config_file,
        platform=platform.value,
        convert=True,
        mssp=mssp,
        sentinel_xdr=sentinel_xdr,
        module=module,
        debug=debug,
        json=json_log,
        json_output=json_output,
        json_stdout=json_stdout,
    )

    logger.info(f"Convert mode was selected - path selected: {rules}")

    base_config = load_base_config(config_file)

    if is_raw_rule(params, base_config):
        logger.info("Raw rules are not subject to Sigma conversion.")
        raise typer.Exit(code=0)

    conversion_error, _search_warning = convert_rules(
        params,
        load_platform_config(params, config_file),
        base_config,
        logger_param,
    )

    if conversion_error:
        logger.error("Conversion errors found")
        raise typer.Exit(code=1)
    else:
        logger.info("Successfully converted the rules")
        raise typer.Exit(code=0)
