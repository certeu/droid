"""
Tests of the --convert option
"""

import pytest

from droid.__main__ import main

def test_check():
    """Simply test --help of droid"""
    with pytest.raises(SystemExit) as error:
        main(["--help"])
    assert error.type == SystemExit
    assert error.value.code == 0

def test_convert_valid_file_default():
    """Test of valid sigma rule with default pipeline"""
    with pytest.raises(SystemExit) as error:
         main(["--convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/valid/convert_valid_rule.yml", "--config-file", "tests/files/test_config.toml"])
    assert error.type == SystemExit
    assert error.value.code == 0

def test_convert_invalid_file_default():
    """Test of invalid sigma rule with default pipeline"""
    with pytest.raises(SystemExit) as error:
         main(["--convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/invalid/convert_invalid_rule.yml", "--config-file", "tests/files/test_config.toml"])
    assert error.type == SystemExit
    assert error.value.code == 1

def test_convert_valid_file_custom():
    """Test of valid sigma rule with custom pipeline"""
    with pytest.raises(SystemExit) as error:
        main(["--convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/valid/convert_valid_rule.yml", "--config-file", "tests/files/test_config_custom_pipelines.toml"])
    assert error.type == SystemExit
    assert error.value.code == 0

def test_convert_valid_files_directory():
    """Test of multiple valid sigma rules with custom pipeline"""
    with pytest.raises(SystemExit) as error:
        main(["--convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/valid/", "--config-file", "tests/files/test_config_custom_pipelines.toml"])
    assert error.type == SystemExit
    assert error.value.code == 0

def test_convert_invalid_files_directory():
    """Test of multiple invalid sigma rules with custom pipeline"""
    with pytest.raises(SystemExit) as error:
        main(["--convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/invalid/", "--config-file", "tests/files/test_config_custom_pipelines.toml"])
    assert error.type == SystemExit
    assert error.value.code == 1

def test_convert_invalid_file_custom():
    """Test of invalid sigma rule with custom pipeline"""
    with pytest.raises(SystemExit) as error:
        main(["--convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/invalid/convert_invalid_rule.yml", "--config-file", "tests/files/test_config_custom_pipelines.toml"])
    assert error.type == SystemExit
    assert error.value.code == 1