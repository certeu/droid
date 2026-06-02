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

def test_file_has_correlation_detects_in_multidoc():
    """_file_has_correlation must scan every YAML document, not only the first."""
    from droid.convert import Conversion
    assert Conversion._file_has_correlation("tests/files/sigma-rules/valid/convert_valid_correlation_rule.yml") is True
    assert Conversion._file_has_correlation("tests/files/sigma-rules/valid/convert_valid_rule.yml") is False

def test_convert_correlation_rule_with_overrides():
    """Correlation rule uses format_correlation + pipelines_correlation when set.

    Without the overrides, Splunk data_model output crashes on SigmaCorrelationRule
    because finalize_query_data_model reads .logsource directly.
    """
    result = runner.invoke(app, ["rules", "convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/valid/convert_valid_correlation_rule.yml", "--config-file", "tests/files/test_config_correlation.toml"])
    assert result.exit_code == 0

def test_convert_atomic_rule_ignores_correlation_overrides():
    """Atomic rule in a config that defines correlation overrides still uses the
    regular `pipelines` + `format` (i.e. the override only fires for correlation rules)."""
    result = runner.invoke(app, ["rules", "convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/valid/convert_valid_rule.yml", "--config-file", "tests/files/test_config_correlation.toml"])
    assert result.exit_code == 0