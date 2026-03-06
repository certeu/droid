"""
Tests of the convert command
"""

import pytest

from typer.testing import CliRunner
from droid.__main__ import app

runner = CliRunner()

def test_check():
    """Simply test --help of droid"""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0

def test_convert_valid_file_default():
    """Test of valid sigma rule with default pipeline"""
    result = runner.invoke(app, ["rules", "convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/valid/convert_valid_rule.yml", "--config-file", "tests/files/test_config.toml"])
    assert result.exit_code == 0

def test_convert_invalid_file_default():
    """Test of invalid sigma rule with default pipeline"""
    result = runner.invoke(app, ["rules", "convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/invalid/convert_invalid_rule.yml", "--config-file", "tests/files/test_config.toml"])
    assert result.exit_code == 1

def test_convert_valid_file_custom():
    """Test of valid sigma rule with custom pipeline"""
    result = runner.invoke(app, ["rules", "convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/valid/convert_valid_rule.yml", "--config-file", "tests/files/test_config_custom_pipelines.toml"])
    assert result.exit_code == 0

def test_convert_valid_files_directory():
    """Test of multiple valid sigma rules with custom pipeline"""
    result = runner.invoke(app, ["rules", "convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/valid/", "--config-file", "tests/files/test_config_custom_pipelines.toml"])
    assert result.exit_code == 0

def test_convert_invalid_files_directory():
    """Test of multiple invalid sigma rules with custom pipeline"""
    result = runner.invoke(app, ["rules", "convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/invalid/", "--config-file", "tests/files/test_config_custom_pipelines.toml"])
    assert result.exit_code == 1

def test_convert_invalid_file_custom():
    """Test of invalid sigma rule with custom pipeline"""
    result = runner.invoke(app, ["rules", "convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/invalid/convert_invalid_rule.yml", "--config-file", "tests/files/test_config_custom_pipelines.toml"])
    assert result.exit_code == 1

def test_convert_valid_file_with_customer_filter():
    """Test conversion of valid sigma rule with customer-specific filter applied"""
    result = runner.invoke(app, ["rules", "convert", "--platform", "microsoft_xdr", "--rules", "tests/files/sigma-rules/valid/convert_valid_rule.yml", "--config-file", "tests/files/test_config.toml", "--mssp"])
    assert result.exit_code == 0