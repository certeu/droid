"""
Tests of the export command
"""

import pytest

from typer.testing import CliRunner
from droid.__main__ import app

runner = CliRunner()

def test_check():
    """Simply test --help of droid"""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
