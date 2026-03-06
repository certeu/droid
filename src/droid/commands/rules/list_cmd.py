"""List command – list items extracted from rules."""

import typer
from rich import print

from droid.registry import register_command
from droid.config import (
    ListItem,
    build_logger_param,
    build_parameters,
    get_global_opts,
    init_logger,
)
from droid.list import list_keys


@register_command("rules", "list")
def list_cmd(
    ctx: typer.Context,
    item: ListItem = typer.Argument(..., help="Item type to list"),
    rules: str = typer.Option(..., "--rules", "-r", help="Rules path"),
) -> None:
    """List items from the detection rules (unique_fields, pipelines, validators)."""
    debug, json_log, json_stdout, json_output = get_global_opts(ctx)
    logger_param = build_logger_param(debug, json_log, json_stdout, json_output)
    logger = init_logger(logger_param)

    params = build_parameters(
        rules=rules,
        list=item.value,
        debug=debug,
        json=json_log,
        json_output=json_output,
        json_stdout=json_stdout,
    )

    logger.info(f"List mode was selected - path selected: {rules}")
    list_keys(params, logger_param)
