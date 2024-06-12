"""
Tests of the --validate option
"""

import pytest

from droid.__main__ import main

def test_check():
    """Simply test --help of droid"""
    with pytest.raises(SystemExit) as error:
        main(["--help"])
    assert error.type == SystemExit
    assert error.value.code == 0

def test_validate_valid_file():
    with pytest.raises(SystemExit) as error:
       main(["--validate", "--rules", "tests/files/sigma-rules/valid/valid_rule.yml", "--config-file", "tests/files/test_config.toml"])
    assert error.type == SystemExit
    assert error.value.code == 0

def test_validate_invalid_file():
    with pytest.raises(SystemExit) as error:
        main(["--validate", "--rules", "tests/files/sigma-rules/invalid/invalid_rule.yml", "--config-file", "tests/files/test_config.toml"])
    assert error.type == SystemExit
    assert error.value.code == 1