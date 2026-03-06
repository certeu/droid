"""
Tests for the `version` command.
"""

import importlib.metadata

from typer.testing import CliRunner

from droid.__main__ import app

runner = CliRunner()


def test_version_exit_code():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0


def test_version_output_format():
    result = runner.invoke(app, ["version"])
    assert result.output.startswith("droid ")


def test_version_matches_metadata(monkeypatch):
    """Version shown matches the installed package metadata when available."""
    monkeypatch.setattr(importlib.metadata, "version", lambda _: "9.9.9")
    result = runner.invoke(app, ["version"])
    assert "9.9.9" in result.output


def test_version_fallback_to_setup_cfg(monkeypatch):
    """Falls back to setup.cfg when the package is not installed."""
    monkeypatch.setattr(
        importlib.metadata,
        "version",
        lambda _: (_ for _ in ()).throw(importlib.metadata.PackageNotFoundError("detect-droid")),
    )
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    # Should still print a version string, not "unknown"
    assert result.output.strip() != "droid unknown"
