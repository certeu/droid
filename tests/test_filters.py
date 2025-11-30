"""
Tests for the customer filters feature (filters.py)

In MSSP mode, customer_filters_directory is specified directly in export_list_mssp:

    [platforms.microsoft_xdr.export_list_mssp.Zoidberg]
    tenant_id = "406a174b-e315-48bd-aa0a-cdaddc44250b"
    customer_name = "Zoidberg"
    customer_filters_directory = "filters/zoidberg/"
"""

import pytest
import os
from pathlib import Path
from droid.filters import CustomerFilters


# Test fixtures
@pytest.fixture
def logger_param():
    return {
        "debug_mode": False,
        "json_enabled": False,
        "json_stdout": False,
        "log_file": None
    }


@pytest.fixture
def sample_rule_content():
    """Sample rule content for testing"""
    return {
        "id": "test-rule-001",
        "title": "Files Added to an Archive Using RAR exe",
        "name": "files_added_to_an_archive_using_rar_exe",
        "description": "Test rule",
        "logsource": {
            "product": "windows",
            "category": "process_creation"
        },
        "detection": {
            "selection": {
                "Image|endswith": "\\rar.exe"
            },
            "condition": "selection"
        },
        "level": "medium"
    }


class TestCustomerFilters:
    """Tests for CustomerFilters class"""

    def test_init_creates_empty_filters_list(self, logger_param):
        """Test that CustomerFilters initializes with empty filters"""
        cf = CustomerFilters(logger_param)
        assert cf.has_filters() is False
        assert cf.get_customer_name() is None
        assert cf.get_filter_directory() is None

    def test_load_filters_from_valid_directory(self, logger_param):
        """Test loading filters from a valid directory"""
        cf = CustomerFilters(logger_param)
        
        # Use the test filters directory
        filter_dir = "tests/files/filters/pizza_planet"
        if Path(filter_dir).exists():
            result = cf.load_filters_from_directory(filter_dir, "Pizza Planet")
            assert result is True
            assert cf.get_customer_name() == "Pizza Planet"
            assert cf.get_filter_directory() == filter_dir
            assert cf.has_filters() is True

    def test_load_filters_from_nonexistent_directory(self, logger_param):
        """Test loading filters from a non-existent directory returns False"""
        cf = CustomerFilters(logger_param)
        result = cf.load_filters_from_directory("/nonexistent/path", "Test Customer")
        
        assert result is False
        assert cf.has_filters() is False

    def test_clear_removes_all_data(self, logger_param):
        """Test that clear() removes all loaded data"""
        cf = CustomerFilters(logger_param)
        
        # Set some data manually
        cf._customer_name = "Test"
        cf._filter_directory = "/some/path"
        cf._filters = [{"title": "test"}]
        
        cf.clear()
        
        assert cf.has_filters() is False
        assert cf.get_customer_name() is None
        assert cf.get_filter_directory() is None

    def test_filter_applies_based_on_logsource(self, logger_param):
        """Test that filters are matched based on logsource"""
        cf = CustomerFilters(logger_param)
        cf._customer_name = "Test Customer"
        cf._filters = [
            {
                "title": "Test Filter",
                "logsource": {"product": "windows", "category": "process_creation"},
                "filter": {}
            }
        ]
        
        rule_content = {
            "title": "Test Rule",
            "logsource": {"product": "windows", "category": "process_creation"}
        }
        
        applicable = cf.get_filters_for_rule(rule_content)
        assert len(applicable) == 1

    def test_filter_not_applied_when_logsource_mismatch(self, logger_param):
        """Test that filters are not applied when logsource doesn't match"""
        cf = CustomerFilters(logger_param)
        cf._customer_name = "Test Customer"
        cf._filters = [
            {
                "title": "Test Filter",
                "logsource": {"product": "windows", "category": "network_connection"},
                "filter": {}
            }
        ]
        
        rule_content = {
            "title": "Test Rule",
            "logsource": {"product": "windows", "category": "process_creation"}
        }
        
        applicable = cf.get_filters_for_rule(rule_content)
        assert len(applicable) == 0

    def test_filter_applied_based_on_rules_list(self, logger_param):
        """Test that filters are matched based on rules list"""
        cf = CustomerFilters(logger_param)
        cf._customer_name = "Test Customer"
        cf._filters = [
            {
                "title": "Test Filter",
                "logsource": {"product": "windows"},
                "filter": {
                    "rules": ["test_rule_name"]
                }
            }
        ]
        
        rule_content = {
            "title": "Test Rule Name",  # Will be converted to test_rule_name
            "logsource": {"product": "windows"}
        }
        
        applicable = cf.get_filters_for_rule(rule_content)
        assert len(applicable) == 1

    def test_filter_not_applied_when_rule_not_in_list(self, logger_param):
        """Test that filters with rules list don't apply to non-matching rules"""
        cf = CustomerFilters(logger_param)
        cf._customer_name = "Test Customer"
        cf._filters = [
            {
                "title": "Test Filter",
                "logsource": {"product": "windows"},
                "filter": {
                    "rules": ["specific_rule_name"]
                }
            }
        ]
        
        rule_content = {
            "title": "Different Rule Name",
            "logsource": {"product": "windows"}
        }
        
        applicable = cf.get_filters_for_rule(rule_content)
        assert len(applicable) == 0

    def test_filter_customer_name_validation(self, logger_param):
        """Test that filters with customer_name are only applied to matching customers"""
        cf = CustomerFilters(logger_param)
        cf._customer_name = "Customer A"
        cf._filters = [
            {
                "title": "Test Filter",
                "logsource": {"product": "windows"},
                "customer_name": "Customer B",  # Different customer
                "filter": {}
            }
        ]
        
        rule_content = {
            "title": "Test Rule",
            "logsource": {"product": "windows"}
        }
        
        applicable = cf.get_filters_for_rule(rule_content)
        assert len(applicable) == 0  # Should not apply due to customer mismatch
