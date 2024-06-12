"""
Tests of the --export option
"""

import pytest

from droid.__main__ import main

def test_check():
    """Simply test --help of droid"""
    with pytest.raises(SystemExit) as error:
        main(["--help"])
    assert error.type == SystemExit
    assert error.value.code == 0
