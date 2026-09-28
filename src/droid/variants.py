"""
Module handling the log source variants

A log source can be served by more than one telemetry source: Sysmon *and*
BitDefender for windows/process_creation, Azure WAF *and* AGWAccessLogs for
webserver. Each of those is a *variant*: its own pipeline group, producing its
own query, deployed as its own object on the platform.

One variant per log source is the *primary*. It deploys under the bare Sigma
UUID and the bare rule title, exactly as droid behaved before variants existed,
so introducing a variant never disturbs an already-deployed rule. Every other
variant derives a stable identity from the Sigma id and its own name.
"""

import uuid

from copy import deepcopy
from dataclasses import dataclass

DEFAULT_VARIANT = "default"

SIGMA_LOGSOURCE_FIELDS = ["category", "product", "service"]


class VariantConfigError(Exception):
    """Raised when the variants declared for a log source are inconsistent"""


@dataclass(frozen=True)
class Variant:
    """One telemetry source serving a log source

    Attributes:
        name: the variant name declared in the config, e.g. "bitdefender"
        group: the pipeline config group it comes from
        config: the pipeline group parameters
        is_primary: whether it keeps the bare Sigma id and title
        is_named: whether the group declared a `variant` name, which is what
                  opts it into the per-target allowlists
    """

    name: str
    group: str
    config: dict
    is_primary: bool
    is_named: bool = True

    @property
    def identity_key(self) -> str | None:
        """The variant name used to derive the platform identity

        None for the primary, which keeps the identity it already deploys under.
        """
        return None if self.is_primary else self.name


def _rule_logsource(rule_content: dict) -> dict:
    return {
        key: value
        for key, value in rule_content["logsource"].items()
        if key in SIGMA_LOGSOURCE_FIELDS
    }


def resolve_variants(rule_content: dict, pipelines_config: dict) -> list[Variant]:
    """Resolve every pipeline config group serving a rule's log source

    A single matching group is the primary whatever it declares, which is how
    every config predating variants keeps behaving. As soon as a log source is
    served by more than one group, each must name its `variant` and exactly one
    must claim `primary`, so the identity a rule deploys under is never a
    matter of dict ordering.

    Return: a list of Variant, primary first, then variants in config order
    """

    rule_logsource = _rule_logsource(rule_content)

    matches = [
        (group, params)
        for group, params in pipelines_config.items()
        if {k: v for k, v in params.items() if k in SIGMA_LOGSOURCE_FIELDS} == rule_logsource
    ]

    if not matches:
        return []

    if len(matches) == 1:
        group, params = matches[0]
        return [
            Variant(
                name=params.get("variant", DEFAULT_VARIANT),
                group=group,
                config=params,
                is_primary=True,
                is_named="variant" in params,
            )
        ]

    logsource = ", ".join(f"{k}={v}" for k, v in sorted(rule_logsource.items()))

    unnamed = [group for group, params in matches if "variant" not in params]
    if unnamed:
        raise VariantConfigError(
            f"Log source ({logsource}) is served by {len(matches)} pipeline groups, "
            f"so each must declare a 'variant' name. Missing on: {', '.join(sorted(unnamed))}"
        )

    names = [params["variant"] for _, params in matches]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise VariantConfigError(
            f"Log source ({logsource}) declares the variant name(s) "
            f"{', '.join(duplicates)} more than once. Variant names must be unique."
        )

    primaries = [group for group, params in matches if params.get("primary")]
    if len(primaries) != 1:
        raise VariantConfigError(
            f"Log source ({logsource}) is served by {len(matches)} pipeline groups, "
            f"so exactly one must declare 'primary = true' to keep the bare rule id "
            f"and title. Found {len(primaries)}"
            + (f": {', '.join(sorted(primaries))}" if primaries else "")
        )

    variants = [
        Variant(
            name=params["variant"],
            group=group,
            config=params,
            is_primary=bool(params.get("primary")),
        )
        for group, params in matches
    ]

    return sorted(variants, key=lambda variant: not variant.is_primary)


def select_variants(variants: list[Variant], allowlist: list[str] | None) -> list[Variant]:
    """Narrow the resolved variants to those a target actually carries

    An absent allowlist selects everything the platform config declares, which
    keeps single-variant configs behaving as before. An allowlist names the
    telemetry a given workspace or customer has — including dropping the
    primary, for a customer that only carries the alternative source.

    The allowlist is one list per target, covering every log source on the
    platform, so it only ever narrows the log sources that actually *name* their
    variants. A log source served by a single unnamed pipeline group — which is
    nearly all of them — offers no choice to make, and is served to everyone.
    Filtering those on the allowlist would mean adding `variants` to one customer
    silently stopped every ordinary rule in the repository from reaching them.

    Return: a list of Variant in resolution order
    """

    if allowlist is None:
        return list(variants)

    return [
        variant for variant in variants
        if not variant.is_named or variant.name in allowlist
    ]


def customer_serves_variant(rule_content: dict, customer_config: dict) -> bool:
    """Whether an MSSP customer carries the telemetry a rule was converted from

    The conversion fans a rule out over every variant its log source declares,
    but a customer only has some of those sources. Their export_list_mssp entry
    names the ones they have under `variants`; without that key they receive
    everything, which is what every configuration predating variants expects.

    A rule content carrying no `_droid_variant`, or one whose log source never
    named its variants, offers no telemetry choice to match the allowlist
    against and is deployed as it always was. See `select_variants` for why
    unnamed log sources must not be filtered.

    Return: True when the rule should be deployed to that customer
    """

    allowlist = customer_config.get("variants")
    if allowlist is None:
        return True

    variant = rule_content.get("_droid_variant")
    if variant is None or not variant.get("is_named", True):
        return True

    return variant["name"] in allowlist


def variant_rule_content(rule_content: dict, variant: Variant) -> dict:
    """Build the rule content a variant deploys under

    The platforms read `id` and `title` straight off the rule content, so the
    variant identity is substituted there rather than threaded through every
    create/get/remove signature. The original is left untouched — it is reused
    for the next variant and the next customer.

    The copy is deep: the same rule content is fanned out over every variant and
    then over every MSSP customer, so a sub-dict shared with the original would
    carry any edit a platform makes into every later iteration of the run.

    `_droid_variant` carries what the platforms need beyond identity: the
    pipeline group parameters (Splunk reads its suppression override from it)
    and a pointer back to the Sigma rule this was derived from. Those parameters
    are shared deliberately — they are read-only config, not per-rule state.

    Return: a dict with the rule content for that variant
    """

    content = deepcopy(rule_content)
    content["id"] = derive_rule_id(rule_content["id"], variant.identity_key)
    content["title"] = derive_title(rule_content["title"], variant.identity_key)
    content["_droid_variant"] = {
        "name": variant.name,
        "group": variant.group,
        "config": variant.config,
        "is_primary": variant.is_primary,
        "is_named": variant.is_named,
        "parent_id": rule_content["id"],
        "parent_title": rule_content["title"],
    }

    return content


def derive_rule_id(sigma_id: str, variant: str | None) -> str:
    """Resolve the platform rule id for a variant of a rule

    The primary variant (``variant`` is None) keeps the Sigma UUID. Any other
    variant gets a UUIDv5 built in the namespace of the rule it belongs to, so
    the id is stable across runs, unique per (rule, variant) and needs no state
    file to reproduce.

    Return: a str with the platform rule id
    """

    if not variant:
        return sigma_id

    return str(uuid.uuid5(uuid.UUID(str(sigma_id)), variant))


def derive_title(title: str, variant: str | None) -> str:
    """Resolve the platform rule title for a variant of a rule

    Splunk keys its saved searches by name, so each variant needs its own.

    Return: a str with the platform rule title
    """

    if not variant:
        return title

    return f"{title} [{variant}]"
