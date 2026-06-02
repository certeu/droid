"""Helpers for loading Sigma rule YAML files."""
import yaml


def load_rule_content(rule_file):
    """Load a rule file and return its primary content.

    For multi-doc correlation files, correlation-doc fields overlay the
    atomic doc so identity (title, id, level, …) comes from the correlation
    rule. `custom` is deep-merged; correlation wins on conflict.
    """
    with open(rule_file, "r", encoding="utf-8") as stream:
        docs = list(yaml.safe_load_all(stream))

    if not docs:
        return None

    primary = docs[0]
    if not isinstance(primary, dict):
        return primary

    correlation_doc = next(
        (doc for doc in docs[1:] if isinstance(doc, dict) and "correlation" in doc),
        None,
    )
    if correlation_doc is None:
        return primary

    merged = {**primary, **correlation_doc}
    if primary.get("custom") and correlation_doc.get("custom"):
        merged["custom"] = {**primary["custom"], **correlation_doc["custom"]}

    return merged
