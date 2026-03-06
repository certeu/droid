"""
Main class
"""

import importlib
import importlib.metadata
import pkgutil
import sys
from typing import Optional

import typer

from droid.registry import get_registry

app = typer.Typer(
    name="droid",
    help="Detection Rules Optimization Integration Deployment",
    add_completion=False,
)

# ---------------------------------------------------------------------------
# Top-level commands
# ---------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Show the current version of droid."""
    try:
        v = importlib.metadata.version("detect-droid")
    except importlib.metadata.PackageNotFoundError:
        import configparser, pathlib
        cfg = configparser.ConfigParser()
        cfg.read(pathlib.Path(__file__).resolve().parents[2] / "setup.cfg")
        v = cfg.get("metadata", "version", fallback="unknown")
    typer.echo(f"droid {v}")


# ---------------------------------------------------------------------------
# Global options (shared across all sub-commands via ctx.obj)
# ---------------------------------------------------------------------------

@app.callback()
def _global_options(
    ctx: typer.Context,
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debugging"),
    json_log: bool = typer.Option(False, "--json", "-j", help="Drop a JSON log file"),
    json_output: Optional[str] = typer.Option(None, "--json-output", help="Optional path for JSON log file"),
    json_stdout: bool = typer.Option(False, "--json-stdout", help="Enable logging to stdout in JSON"),
) -> None:
    """Global options applied before any sub-command."""
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug
    ctx.obj["json"] = json_log
    ctx.obj["json_output"] = json_output
    ctx.obj["json_stdout"] = json_stdout


# ---------------------------------------------------------------------------
# Dynamic command loading
# ---------------------------------------------------------------------------

def _load_command_group(package_dotpath: str) -> None:
    """Import every module inside *package_dotpath* so @register_command decorators fire."""
    package = importlib.import_module(package_dotpath)
    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        importlib.import_module(f"{package_dotpath}.{module_name}")


def load_all_commands() -> None:
    """Discover and import all command-group packages under droid.commands."""
    import droid.commands

    for _, group_name, is_pkg in pkgutil.iter_modules(droid.commands.__path__):
        if is_pkg:
            _load_command_group(f"droid.commands.{group_name}")


def register_with_typer() -> None:
    """Create a Typer sub-app per group and attach every registered command."""
    group_apps: dict[str, typer.Typer] = {}

    for group, name, func in get_registry():
        if group not in group_apps:
            group_apps[group] = typer.Typer(help=f"{group.capitalize()} commands")
            app.add_typer(group_apps[group], name=group)
        group_apps[group].command(name=name)(func)


# ---------------------------------------------------------------------------
# Ensure commands are loaded exactly once (import-safe)
# ---------------------------------------------------------------------------

_commands_loaded = False


def _ensure_commands_loaded() -> None:
    global _commands_loaded
    if not _commands_loaded:
        load_all_commands()
        register_with_typer()
        _commands_loaded = True


_ensure_commands_loaded()


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    _ensure_commands_loaded()
    app(prog_name="droid")


if __name__ == "__main__":
    sys.exit(main())
