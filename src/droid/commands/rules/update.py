"""Update command – update rules from an upstream source."""

import typer

from droid.registry import register_command
from droid.config import (
    UpdateSource,
    build_logger_param,
    build_parameters,
    get_global_opts,
    init_logger,
)
from droid.sources.sigmahq import update_sigmahq_core


@register_command("rules", "update")
def update(
    ctx: typer.Context,
    rules: str = typer.Option(..., "--rules", "-r", help="Rules path"),
    source: UpdateSource = typer.Option(..., "--source", "-s", help="Source to update from"),
) -> None:
    """Update rules from an upstream source."""
    debug, json_log, json_stdout, json_output = get_global_opts(ctx)
    logger_param = build_logger_param(debug, json_log, json_stdout, json_output)
    logger = init_logger(logger_param)

    params = build_parameters(
        rules=rules,
        update=source.value,
        debug=debug,
        json=json_log,
        json_output=json_output,
        json_stdout=json_stdout,
    )

    logger.info(f"Update mode was selected for source {source.value} - source selected: {rules}")

    if params.update == "sigmahq-core":
        update_sigmahq_core(params, logger_param)
