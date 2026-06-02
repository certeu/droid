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

def test_load_rule_merges_custom_from_correlation_document(tmp_path):
    """`custom` on the correlation document must surface on the loaded rule_content.

    Without the merge, downstream checks like rule_content.get("custom", {}).get("ignore_search")
    silently miss any override placed on the correlation rule (the last YAML doc),
    because load_rule used to return only the first document.
    """
    from droid.rule_loader import load_rule_content

    rule_file = tmp_path / "correlation_with_custom.yml"
    rule_file.write_text(
        "title: Atomic 1\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "name: atomic_1\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection: {selection: {CommandLine|contains: foo.exe}, condition: selection}\n"
        "---\n"
        "title: Correlation\n"
        "id: 22222222-2222-2222-2222-222222222222\n"
        "correlation: {type: temporal, rules: [atomic_1], timespan: 10m}\n"
        "custom:\n"
        "    ignore_search: true\n"
        "    disabled: true\n"
    )

    loaded = load_rule_content(str(rule_file))

    assert loaded["title"] == "Atomic 1"  # structural primary preserved
    assert loaded["custom"]["ignore_search"] is True
    assert loaded["custom"]["disabled"] is True

def test_load_rule_correlation_custom_overrides_atomic_custom(tmp_path):
    """When both atomic and correlation docs declare `custom`, the correlation wins."""
    from droid.rule_loader import load_rule_content

    rule_file = tmp_path / "both_have_custom.yml"
    rule_file.write_text(
        "title: Atomic\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "name: atomic\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection: {selection: {CommandLine|contains: foo.exe}, condition: selection}\n"
        "custom:\n"
        "    ignore_search: false\n"
        "    earliest_time: -1h\n"
        "---\n"
        "title: Correlation\n"
        "id: 22222222-2222-2222-2222-222222222222\n"
        "correlation: {type: temporal, rules: [atomic], timespan: 10m}\n"
        "custom:\n"
        "    ignore_search: true\n"
    )

    loaded = load_rule_content(str(rule_file))

    assert loaded["custom"]["ignore_search"] is True   # correlation override wins
    assert loaded["custom"]["earliest_time"] == "-1h"  # atomic-only key preserved

def test_load_rule_single_document_unchanged(tmp_path):
    """Single-document rules behave identically to the legacy loader."""
    from droid.rule_loader import load_rule_content

    rule_file = tmp_path / "single.yml"
    rule_file.write_text(
        "title: Solo\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection: {selection: {CommandLine|contains: foo.exe}, condition: selection}\n"
        "custom: {ignore_search: true}\n"
    )

    loaded = load_rule_content(str(rule_file))

    assert loaded["title"] == "Solo"
    assert loaded["custom"] == {"ignore_search": True}

def test_load_rule_custom_on_atomic_only_preserved(tmp_path):
    """Multi-doc correlation file with `custom` only on the atomic doc keeps it intact."""
    from droid.rule_loader import load_rule_content

    rule_file = tmp_path / "atomic_only_custom.yml"
    rule_file.write_text(
        "title: Atomic\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "name: atomic\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection: {selection: {CommandLine|contains: foo.exe}, condition: selection}\n"
        "custom:\n"
        "    ignore_search: true\n"
        "    disabled: true\n"
        "---\n"
        "title: Correlation\n"
        "id: 22222222-2222-2222-2222-222222222222\n"
        "correlation: {type: temporal, rules: [atomic], timespan: 10m}\n"
    )

    loaded = load_rule_content(str(rule_file))

    assert loaded["custom"] == {"ignore_search": True, "disabled": True}

def test_load_rule_multidoc_without_correlation_uses_first(tmp_path):
    """If no document is a correlation rule, no merge happens — first-doc behaviour."""
    from droid.rule_loader import load_rule_content

    rule_file = tmp_path / "two_atomic.yml"
    rule_file.write_text(
        "title: Atomic 1\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection: {selection: {CommandLine|contains: foo.exe}, condition: selection}\n"
        "custom: {ignore_search: true}\n"
        "---\n"
        "title: Atomic 2\n"
        "id: 22222222-2222-2222-2222-222222222222\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection: {selection: {CommandLine|contains: bar.exe}, condition: selection}\n"
        "custom: {ignore_search: false, disabled: true}\n"
    )

    loaded = load_rule_content(str(rule_file))

    # Second document is NOT a correlation rule, so its `custom` is ignored.
    assert loaded["title"] == "Atomic 1"
    assert loaded["custom"] == {"ignore_search": True}

def test_load_rule_correlation_custom_only_extra_keys_merged(tmp_path):
    """Correlation `custom` keys are added on top of atomic ones; non-overlapping keys coexist."""
    from droid.rule_loader import load_rule_content

    rule_file = tmp_path / "merge_disjoint.yml"
    rule_file.write_text(
        "title: Atomic\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "name: atomic\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection: {selection: {CommandLine|contains: foo.exe}, condition: selection}\n"
        "custom:\n"
        "    earliest_time: -1h\n"
        "    latest_time: now\n"
        "---\n"
        "title: Correlation\n"
        "id: 22222222-2222-2222-2222-222222222222\n"
        "correlation: {type: temporal, rules: [atomic], timespan: 10m}\n"
        "custom:\n"
        "    ignore_search: true\n"
        "    removed: true\n"
    )

    loaded = load_rule_content(str(rule_file))

    assert loaded["custom"] == {
        "earliest_time": "-1h",
        "latest_time": "now",
        "ignore_search": True,
        "removed": True,
    }

def test_search_rule_short_circuits_on_correlation_ignore_search(tmp_path):
    """End-to-end: `custom.ignore_search` on the correlation doc must skip the search.

    Regression guard for the original bug — before the fix, search would still run
    against the platform because `rule_content.get("custom", {})` only ever saw the
    first atomic doc.
    """
    from droid.search import load_rule, search_rule

    rule_file = tmp_path / "corr_ignore_search.yml"
    rule_file.write_text(
        "title: Atomic\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "name: atomic\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection: {selection: {CommandLine|contains: foo.exe}, condition: selection}\n"
        "---\n"
        "title: Correlation\n"
        "id: 22222222-2222-2222-2222-222222222222\n"
        "correlation: {type: temporal, rules: [atomic], timespan: 10m}\n"
        "custom: {ignore_search: true}\n"
    )

    rule_content = load_rule(str(rule_file))
    assert rule_content["custom"]["ignore_search"] is True

    class _Params:
        platform = "splunk"  # would otherwise try to call splunk

    # platform=None would crash inside search_rule_splunk; the early-return must fire first.
    error, search_warning = search_rule(
        _Params(), rule_content, "irrelevant-query", None, str(rule_file),
        False, False, {"json_enabled": False, "log_file": None},
    )
    assert error is False
    assert search_warning is False