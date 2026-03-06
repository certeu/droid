"""Command packages for the droid CLI.

Each subpackage represents a command group (rules, deploy, sources).
Command modules use ``@register_command(group, name)`` to register themselves.
Modules are discovered dynamically by ``__main__.py`` -- no manual imports needed.
"""
