"""Validate command – validate Sigma rules."""

import typer
from rich import print

from droid.registry import register_command
from droid.config import (
    build_logger_param,
    build_parameters,
    get_global_opts,
    init_logger,
    is_raw_rule,
    load_base_config,
)
from droid.validate import validate_rules


@register_command("rules", "validate")
def validate(
    ctx: typer.Context,
    rules: str = typer.Option(..., "--rules", "-r", help="Rules path"),
    config_file: str = typer.Option(..., "--config-file", "-c", help="DROID configuration file path"),
) -> None:
    """Validate the Sigma detection rules."""
    debug, json_log, json_stdout, json_output = get_global_opts(ctx)
    logger_param = build_logger_param(debug, json_log, json_stdout, json_output)
    logger = init_logger(logger_param)

    params = build_parameters(
        rules=rules,
        config_file=config_file,
        validate=True,
        debug=debug,
        json=json_log,
        json_output=json_output,
        json_stdout=json_stdout,
    )

    logger.info(f"Validation mode was selected - path selected: {rules}")

    base_config = load_base_config(config_file)

    if is_raw_rule(params, base_config):
        logger.info("Raw rules are not subject to Sigma validation.")
        raise typer.Exit(code=0)

    rule_error = validate_rules(params, False, base_config, logger_param)

    if rule_error:
        logger.error("Validation issues found")
        raise typer.Exit(code=1)
    else:
        logger.info("No validation issues found")
        raise typer.Exit(code=0)
