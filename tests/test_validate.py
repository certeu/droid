"""
Tests of the validate command
"""

import pytest

from typer.testing import CliRunner
from droid.__main__ import app

runner = CliRunner()

def test_check():
    """Simply test --help of droid"""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0

def test_validate_valid_file():
    result = runner.invoke(app, ["rules", "validate", "--rules", "tests/files/sigma-rules/valid/valid_rule.yml", "--config-file", "tests/files/test_config.toml"])
    assert result.exit_code == 0

def test_validate_invalid_file():
    result = runner.invoke(app, ["rules", "validate", "--rules", "tests/files/sigma-rules/invalid/invalid_rule.yml", "--config-file", "tests/files/test_config.toml"])
    assert result.exit_code == 1