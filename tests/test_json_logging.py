"""
Tests of the --json option
"""

import pytest

from typer.testing import CliRunner
from droid.__main__ import app
from os import path

runner = CliRunner()

def test_check():
    """Simply test --help of droid"""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0

def test_convert_valid_file_default_json():
    """Test of valid sigma rule with default pipeline and json output"""
    result = runner.invoke(app, ["--json", "rules", "convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/valid/convert_valid_rule.yml", "--config-file", "tests/files/test_config.toml"])
    assert path.exists("droid.log")
    assert result.exit_code == 0
