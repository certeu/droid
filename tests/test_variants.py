"""
Tests of the log source variants support
"""

import pytest


SIGMA_ID = "8a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"


def test_primary_variant_keeps_the_sigma_id():
    """The primary variant must deploy under the bare Sigma UUID.

    This is what keeps every already-deployed rule in place — if the primary
    ever derived an id, every existing Sentinel analytic rule would be orphaned.
    """
    from droid.variants import derive_rule_id

    assert derive_rule_id(SIGMA_ID, None) == SIGMA_ID


def test_non_primary_variant_derives_a_distinct_stable_uuid():
    """A named variant gets its own UUID, derived from the Sigma id."""
    import uuid

    from droid.variants import derive_rule_id

    derived = derive_rule_id(SIGMA_ID, "edr")

    assert derived != SIGMA_ID
    uuid.UUID(derived)  # must be a well-formed UUID for the Sentinel API
    # Deterministic: the same inputs always produce the same id, across runs.
    assert derived == derive_rule_id(SIGMA_ID, "edr")


def test_different_variants_of_the_same_rule_do_not_collide():
    """Two variants of one rule must never resolve to the same platform id."""
    from droid.variants import derive_rule_id

    assert derive_rule_id(SIGMA_ID, "waf") != derive_rule_id(SIGMA_ID, "agw")


def test_same_variant_of_different_rules_do_not_collide():
    """The derivation is namespaced per rule, not global."""
    from droid.variants import derive_rule_id

    other = "11111111-2222-4333-8444-555555555555"
    assert derive_rule_id(SIGMA_ID, "agw") != derive_rule_id(other, "agw")


def test_primary_variant_keeps_the_title():
    """Splunk keys saved searches by title — the primary must keep the bare one."""
    from droid.variants import derive_title

    assert derive_title("Suspicious Process Creation", None) == "Suspicious Process Creation"


def test_non_primary_variant_suffixes_the_title():
    """A named variant gets a suffixed, human-readable saved-search name."""
    from droid.variants import derive_title

    assert derive_title("Suspicious Process Creation", "edr") == (
        "Suspicious Process Creation [edr]"
    )


# ---------------------------------------------------------------------------
# Resolution of the matching pipeline groups
# ---------------------------------------------------------------------------

PROCESS_CREATION = {"logsource": {"category": "process_creation", "product": "windows"}}

SYSMON_GROUP = {
    "pipelines": ["splunk_windows"],
    "product": "windows",
    "category": "process_creation",
}
EDR_GROUP = {
    "pipelines": ["splunk_edr"],
    "product": "windows",
    "category": "process_creation",
    "variant": "edr",
}


def test_single_group_without_variant_keys_is_the_primary():
    """Every pre-existing config has exactly one group per log source.

    It must resolve to a single primary variant so the rule keeps deploying
    under its bare id and title.
    """
    from droid.variants import resolve_variants

    resolved = resolve_variants(PROCESS_CREATION, {"windows_process_creation": SYSMON_GROUP})

    assert len(resolved) == 1
    assert resolved[0].is_primary is True
    assert resolved[0].identity_key is None
    assert resolved[0].group == "windows_process_creation"


def test_non_matching_logsource_resolves_to_no_variant():
    """A rule no group claims is unsupported, as before."""
    from droid.variants import resolve_variants

    resolved = resolve_variants(
        {"logsource": {"category": "network_connection", "product": "windows"}},
        {"windows_process_creation": SYSMON_GROUP},
    )

    assert resolved == []


def test_two_matching_groups_both_resolve_with_the_primary_first():
    """The fan-out: one rule, one log source, two telemetry sources."""
    from droid.variants import resolve_variants

    resolved = resolve_variants(
        PROCESS_CREATION,
        {
            "windows_process_creation": {**SYSMON_GROUP, "variant": "sysmon", "primary": True},
            "windows_process_creation_edr": EDR_GROUP,
        },
    )

    assert [v.name for v in resolved] == ["sysmon", "edr"]
    assert [v.is_primary for v in resolved] == [True, False]
    # Only the non-primary derives an identity.
    assert resolved[0].identity_key is None
    assert resolved[1].identity_key == "edr"


def test_two_matching_groups_without_a_primary_is_a_config_error():
    """Today two matching groups are a silent coin flip. Make it loud instead."""
    from droid.variants import VariantConfigError, resolve_variants

    with pytest.raises(VariantConfigError, match="primary"):
        resolve_variants(
            PROCESS_CREATION,
            {
                "windows_process_creation": {**SYSMON_GROUP, "variant": "sysmon"},
                "windows_process_creation_edr": EDR_GROUP,
            },
        )


def test_two_matching_groups_declaring_the_same_variant_is_a_config_error():
    """Duplicate variant names would collide on a single derived id."""
    from droid.variants import VariantConfigError, resolve_variants

    with pytest.raises(VariantConfigError, match="sysmon"):
        resolve_variants(
            PROCESS_CREATION,
            {
                "group_a": {**SYSMON_GROUP, "variant": "sysmon", "primary": True},
                "group_b": {**SYSMON_GROUP, "variant": "sysmon"},
            },
        )


def test_two_matching_groups_declaring_two_primaries_is_a_config_error():
    """Exactly one variant may keep the bare identity."""
    from droid.variants import VariantConfigError, resolve_variants

    with pytest.raises(VariantConfigError, match="primary"):
        resolve_variants(
            PROCESS_CREATION,
            {
                "group_a": {**SYSMON_GROUP, "variant": "sysmon", "primary": True},
                "group_b": {**EDR_GROUP, "primary": True},
            },
        )


def test_unnamed_group_alongside_a_variant_is_a_config_error():
    """Once a log source fans out, every group must say which variant it is."""
    from droid.variants import VariantConfigError, resolve_variants

    with pytest.raises(VariantConfigError, match="variant"):
        resolve_variants(
            PROCESS_CREATION,
            {
                "windows_process_creation": SYSMON_GROUP,  # no variant, no primary
                "windows_process_creation_edr": EDR_GROUP,
            },
        )


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

def _two_variants():
    from droid.variants import resolve_variants

    return resolve_variants(
        PROCESS_CREATION,
        {
            "windows_process_creation": {**SYSMON_GROUP, "variant": "sysmon", "primary": True},
            "windows_process_creation_edr": EDR_GROUP,
        },
    )


def test_no_allowlist_selects_every_variant():
    """Default is to deploy everything the platform config declares."""
    from droid.variants import select_variants

    assert [v.name for v in select_variants(_two_variants(), None)] == ["sysmon", "edr"]


def test_allowlist_narrows_to_the_named_variants():
    """A customer entry lists the telemetry that customer actually has."""
    from droid.variants import select_variants

    assert [v.name for v in select_variants(_two_variants(), ["edr"])] == ["edr"]


def test_allowlist_can_drop_the_primary():
    """A customer with only AGWAccessLogs and no WAF must be expressible."""
    from droid.variants import select_variants

    selected = select_variants(_two_variants(), ["edr"])

    assert [v.is_primary for v in selected] == [False]
    assert selected[0].identity_key == "edr"


def test_allowlist_does_not_narrow_a_log_source_that_names_no_variants():
    """One allowlist covers every log source on the platform, so it can only
    narrow the ones offering a choice.

    Nearly every log source is served by a single pipeline group with no
    `variant` key. Were those filtered too, adding `variants` to a customer to
    pick their process_creation source would silently stop every other rule in
    the repository from reaching them.
    """
    from droid.variants import resolve_variants, select_variants

    variants = resolve_variants(PROCESS_CREATION, {"windows_process_creation": SYSMON_GROUP})

    assert [v.name for v in select_variants(variants, ["edr"])] == ["default"]


def test_allowlist_narrows_a_sole_variant_that_is_named():
    """Naming a `variant` on a group is what opts it into the allowlists, which
    is the escape hatch for withholding a single-source log source."""
    from droid.variants import resolve_variants, select_variants

    variants = resolve_variants(
        PROCESS_CREATION, {"windows_process_creation": {**SYSMON_GROUP, "variant": "sysmon"}}
    )

    assert select_variants(variants, ["edr"]) == []
    assert [v.name for v in select_variants(variants, ["sysmon"])] == ["sysmon"]


# ---------------------------------------------------------------------------
# Per-variant rule content
# ---------------------------------------------------------------------------

def _rule_content():
    return {
        "title": "Suspicious Process Creation",
        "id": SIGMA_ID,
        "logsource": {"category": "process_creation", "product": "windows"},
        "custom": {"disabled": True},
    }


def test_primary_rule_content_keeps_id_and_title():
    """The primary deploys under exactly the identity it always has."""
    from droid.variants import variant_rule_content

    primary = _two_variants()[0]
    content = variant_rule_content(_rule_content(), primary)

    assert content["id"] == SIGMA_ID
    assert content["title"] == "Suspicious Process Creation"


def test_variant_rule_content_carries_the_derived_identity():
    """Platforms read id and title straight off rule_content, so substitute there."""
    from droid.variants import derive_rule_id, variant_rule_content

    edr = _two_variants()[1]
    content = variant_rule_content(_rule_content(), edr)

    assert content["id"] == derive_rule_id(SIGMA_ID, "edr")
    assert content["title"] == "Suspicious Process Creation [edr]"


def test_variant_rule_content_records_its_parent():
    """Traceability: the deployed object must point back at the Sigma rule."""
    from droid.variants import variant_rule_content

    content = variant_rule_content(_rule_content(), _two_variants()[1])

    assert content["_droid_variant"]["name"] == "edr"
    assert content["_droid_variant"]["parent_id"] == SIGMA_ID
    assert content["_droid_variant"]["parent_title"] == "Suspicious Process Creation"
    assert content["_droid_variant"]["is_primary"] is False


def test_variant_rule_content_does_not_mutate_the_original():
    """The same rule_content is reused for the next variant and the next customer."""
    from droid.variants import variant_rule_content

    original = _rule_content()
    variant_rule_content(original, _two_variants()[1])

    assert original["id"] == SIGMA_ID
    assert original["title"] == "Suspicious Process Creation"
    assert "_droid_variant" not in original


def test_variant_rule_content_preserves_the_rest_of_the_rule():
    """Everything the platforms read beyond identity must survive the copy."""
    from droid.variants import variant_rule_content

    content = variant_rule_content(_rule_content(), _two_variants()[1])

    assert content["custom"] == {"disabled": True}
    assert content["logsource"] == {"category": "process_creation", "product": "windows"}


def test_variant_rule_content_isolates_the_nested_rule_fields():
    """The nested fields must be copies, not the originals.

    The same rule_content is fanned out over every variant and then over every
    MSSP customer. If a platform ever pops or rewrites something inside
    `custom` or `detection` on the content it was handed, a shared sub-dict
    would carry that edit into every later variant and customer of the same run.
    """
    from droid.variants import Variant, variant_rule_content

    rule_content = {
        "id": SIGMA_ID,
        "title": "Suspicious Process Creation",
        "custom": {"disabled": True},
        "detection": {"selection": {"CommandLine|contains": "foo.exe"}},
        "logsource": {"category": "process_creation", "product": "windows"},
    }

    content = variant_rule_content(rule_content, Variant("edr", "g", {}, False))

    content["custom"]["disabled"] = False
    content["detection"]["selection"]["CommandLine|contains"] = "bar.exe"

    assert rule_content["custom"] == {"disabled": True}
    assert rule_content["detection"] == {"selection": {"CommandLine|contains": "foo.exe"}}


def _variant_content(name, is_primary=False):
    """A rule content as the fan-out hands it to a platform."""
    from droid.variants import Variant, variant_rule_content

    return variant_rule_content(
        {"id": SIGMA_ID, "title": "Suspicious process", **PROCESS_CREATION},
        Variant(name=name, group=f"group_{name}", config={}, is_primary=is_primary),
    )


def test_customer_without_an_allowlist_serves_every_variant():
    """Configurations predating variants must keep receiving every rule."""
    from droid.variants import customer_serves_variant

    assert customer_serves_variant(_variant_content("edr"), {"workspace_name": "ws"}) is True


def test_customer_serves_only_the_variants_they_declare():
    """A customer only carrying third-party EDR data must never be sent the Sysmon query."""
    from droid.variants import customer_serves_variant

    customer = {"variants": ["edr"]}

    assert customer_serves_variant(_variant_content("edr"), customer) is True
    assert customer_serves_variant(_variant_content("sysmon", is_primary=True), customer) is False


def test_customer_with_an_allowlist_still_serves_a_rule_carrying_no_variant():
    """A rule converted outside the fan-out carries no telemetry to match against,
    so the allowlist has nothing to exclude it on."""
    from droid.variants import customer_serves_variant

    assert customer_serves_variant({"id": SIGMA_ID, "title": "t", **PROCESS_CREATION},
                                   {"variants": ["edr"]}) is True
