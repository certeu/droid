"""
Shared helpers for loading Sigma rule YAML files.

Sigma correlation rules are stored as multi-document YAML files: the atomic
rules come first and the `correlation:` document comes last. Downstream code
relies on the first (atomic) document for structural fields like `logsource`
and `detection`, but users naturally put droid-specific overrides on the
correlation document, e.g.::

    correlation:
        type: temporal
        ...
    custom:
        ignore_search: True

Without the merge below, `rule_content.get("custom", {})` would always miss
those overrides on correlation rules.
"""
import yaml


def load_rule_content(rule_file):
    """Load a rule file and return its primary content.

    For multi-document correlation files, the `custom` field declared on the
    correlation document is merged onto the first document so that overrides
    such as `ignore_search`, `disabled`, `removed`, `ignore_export_error`,
    Splunk alert keys, etc. apply whether set on the atomic rule or the
    correlation rule. Correlation-document keys win on conflict.
    """
    with open(rule_file, "r", encoding="utf-8") as stream:
        docs = list(yaml.safe_load_all(stream))

    if not docs:
        return None

    primary = docs[0]
    if not isinstance(primary, dict):
        return primary

    for doc in docs[1:]:
        if isinstance(doc, dict) and "correlation" in doc and doc.get("custom"):
            merged = {**(primary.get("custom") or {}), **doc["custom"]}
            return {**primary, "custom": merged}

    return primary
