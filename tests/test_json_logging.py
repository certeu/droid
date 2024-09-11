"""
Tests of the --json option
"""

import pytest

from droid.__main__ import main
from os import path

def test_check():
    """Simply test --help of droid"""
    with pytest.raises(SystemExit) as error:
        main(["--help"])
    assert error.type == SystemExit
    assert error.value.code == 0

def test_convert_valid_file_default_json():
    """Test of valid sigma rule with default pipeline and json output"""
    with pytest.raises(SystemExit) as error:
        main(["--convert", "--platform", "splunk", "--rules", "tests/files/sigma-rules/valid/convert_valid_rule.yml", "--config-file", "tests/files/test_config.toml", "--json"])
    assert path.exists("droid.log")
    assert error.type == SystemExit
    assert error.value.code == 0
