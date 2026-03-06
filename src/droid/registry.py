"""Command registry for droid CLI.

Provides a decorator-based registration pattern to avoid long if/elif/else
chains.  Each command module decorates its entry-point function with
``@register_command(group, name)`` and the main Typer app discovers them
automatically at startup.
"""

from typing import Callable

_registry: list[tuple[str, str, Callable[..., None]]] = []


def register_command(group: str, name: str):
    """Register a CLI command function under *group* / *name*.

    Usage::

        @register_command("rules", "validate")
        def validate(ctx: typer.Context, ...):
            ...
    """

    def decorator(func: Callable[..., None]) -> Callable[..., None]:
        _registry.append((group, name, func))
        return func

    return decorator


def get_registry() -> list[tuple[str, str, Callable[..., None]]]:
    """Return a copy of all registered (group, name, func) tuples."""
    return _registry.copy()
