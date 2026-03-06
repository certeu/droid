"""Platform descriptor registry.

Centralises all per-platform metadata so that config loading, raw-rule
detection, and platform instantiation are driven by data rather than
repeated if/elif chains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from os import environ
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class EnvVarMapping:
    env_var: str          # environment variable name, e.g. "DROID_SPLUNK_USER"
    config_key: str       # key to set in the config dict
    required: bool        # raise when absent; False = silently skip
    nested_key: Optional[str] = None  # write into config[nested_key][config_key]
    default: Any = None               # written when var absent and required=False


@dataclass
class EnvVarGroup:
    mappings: list[EnvVarMapping]
    # None → always apply; callable(config, params) → apply only when True
    condition: Optional[Callable[[dict, Any], bool]] = None


@dataclass
class RawRuleStrategy:
    require_platform_in_path: bool = False  # True for splunk / microsoft_sentinel
    never_raw: bool = False                 # platform can never have raw rules


@dataclass
class PlatformDescriptor:
    toml_key: str                              # [platforms.<toml_key>] TOML section
    env_var_groups: list[EnvVarGroup]
    raw_rule_strategy: RawRuleStrategy
    factory: Callable                          # (config, logger_param, params) -> AbstractPlatform
    # Optional overrides resolved at runtime from parameters:
    toml_key_resolver: Optional[Callable[[Any], str]] = None
    post_load_transform: Optional[Callable[[dict, dict, Any], dict]] = None
    post_load_validator: Optional[Callable[[dict, Any], None]] = None

    def resolve_toml_key(self, params: Any) -> str:
        if self.toml_key_resolver:
            return self.toml_key_resolver(params)
        return self.toml_key


# ---------------------------------------------------------------------------
# Condition helpers
# ---------------------------------------------------------------------------

def _is_deploy_op(cfg: dict, params: Any) -> bool:
    return (
        getattr(params, "export", False)
        or getattr(params, "search", False)
        or getattr(params, "integrity", False)
    )


def _azure_app_auth_needed(cfg: dict, params: Any) -> bool:
    if not _is_deploy_op(cfg, params):
        return False
    if "credential_file" in cfg:
        return False
    search_auth = cfg.get("search_auth", "")
    export_auth = cfg.get("export_auth", "")
    return search_auth == "app" or (export_auth == "app" and getattr(params, "export", False))


def _elastic_basic_auth(cfg: dict, params: Any) -> bool:
    return cfg.get("auth_method") == "basic" and _is_deploy_op(cfg, params)


# ---------------------------------------------------------------------------
# Shared env-var group definitions
# ---------------------------------------------------------------------------

_SPLUNK_ENV_GROUPS: list[EnvVarGroup] = [
    EnvVarGroup(
        condition=_is_deploy_op,
        mappings=[
            EnvVarMapping("DROID_SPLUNK_USER",        "user",                        required=True),
            EnvVarMapping("DROID_SPLUNK_PASSWORD",    "password",                    required=True),
            EnvVarMapping("DROID_SPLUNK_URL",         "url",                         required=False),
            EnvVarMapping("DROID_SPLUNK_WEBHOOK_URL", "action.webhook.param.url",    required=False,
                          nested_key="action"),
        ],
    ),
]

_AZURE_ENV_GROUPS: list[EnvVarGroup] = [
    # Workspace / subscription vars — always apply, optional
    EnvVarGroup(
        condition=None,
        mappings=[
            EnvVarMapping("DROID_AZURE_WORKSPACE_ID",    "workspace_id",    required=False),
            EnvVarMapping("DROID_AZURE_WORKSPACE_NAME",  "workspace_name",  required=False),
            EnvVarMapping("DROID_AZURE_SUBSCRIPTION_ID", "subscription_id", required=False),
            EnvVarMapping("DROID_AZURE_RESOURCE_GROUP",  "resource_group",  required=False),
        ],
    ),
    # Auth-method selection — only on deploy operations, optional
    EnvVarGroup(
        condition=_is_deploy_op,
        mappings=[
            EnvVarMapping("DROID_AZURE_SEARCH_AUTH", "search_auth", required=False),
            EnvVarMapping("DROID_AZURE_EXPORT_AUTH", "export_auth", required=False),
        ],
    ),
    # App-credential vars — conditional on auth_method + absence of credential_file
    EnvVarGroup(
        condition=_azure_app_auth_needed,
        mappings=[
            EnvVarMapping("DROID_AZURE_TENANT_ID",     "tenant_id",     required=True),
            EnvVarMapping("DROID_AZURE_CLIENT_ID",     "client_id",     required=True),
            EnvVarMapping("DROID_AZURE_CLIENT_SECRET", "client_secret", required=True),
            EnvVarMapping("DROID_AZURE_CERT_PASS",     "cert_pass",     required=False, default=None),
        ],
    ),
]

_ELASTIC_ENV_GROUPS: list[EnvVarGroup] = [
    EnvVarGroup(
        condition=_elastic_basic_auth,
        mappings=[
            EnvVarMapping("DROID_ELASTIC_USERNAME", "username", required=True),
            EnvVarMapping("DROID_ELASTIC_PASSWORD", "password", required=True),
        ],
    ),
]


# ---------------------------------------------------------------------------
# Per-platform helpers
# ---------------------------------------------------------------------------

def _azure_validator(cfg: dict, params: Any) -> None:
    valid = ["default", "app"]
    if "search_auth" in cfg and cfg["search_auth"] not in valid:
        raise ValueError(f"Invalid search_auth: {cfg['search_auth']}")
    if "export_auth" in cfg and cfg["export_auth"] not in valid:
        raise ValueError(f"Invalid export_auth: {cfg['export_auth']}")


def _xdr_toml_key_resolver(params: Any) -> str:
    if getattr(params, "sentinel_xdr", False):
        return "microsoft_sentinel"
    return "microsoft_xdr"


def _xdr_post_load_transform(config_section: dict, full_toml: dict, params: Any) -> dict:
    if getattr(params, "sentinel_xdr", False):
        config_section = dict(config_section)  # shallow copy — don't mutate parsed TOML
        config_section["pipelines"] = full_toml["platforms"]["microsoft_xdr"]["pipelines"]
    return config_section


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------

def _splunk_factory(config: dict, logger_param: dict, params: Any):
    from droid.platforms.splunk import SplunkPlatform
    return SplunkPlatform(config, logger_param)


def _sentinel_factory(config: dict, logger_param: dict, params: Any):
    from droid.platforms.sentinel import SentinelPlatform
    return SentinelPlatform(config, logger_param, export_mssp=getattr(params, "mssp", False))


def _xdr_factory(config: dict, logger_param: dict, params: Any):
    if getattr(params, "sentinel_xdr", False):
        from droid.platforms.sentinel import SentinelPlatform
        return SentinelPlatform(config, logger_param, export_mssp=getattr(params, "mssp", False))
    from droid.platforms.ms_xdr import MicrosoftXDRPlatform
    return MicrosoftXDRPlatform(config, logger_param, export_mssp=getattr(params, "mssp", False))


def _elastic_factory(config: dict, logger_param: dict, params: Any):
    from droid.platforms.elastic import ElasticPlatform
    return ElasticPlatform(config, logger_param, params.platform, raw=False)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

PLATFORM_REGISTRY: dict[str, PlatformDescriptor] = {
    "splunk": PlatformDescriptor(
        toml_key="splunk",
        env_var_groups=_SPLUNK_ENV_GROUPS,
        raw_rule_strategy=RawRuleStrategy(require_platform_in_path=True),
        factory=_splunk_factory,
    ),
    "microsoft_sentinel": PlatformDescriptor(
        toml_key="microsoft_sentinel",
        env_var_groups=_AZURE_ENV_GROUPS,
        raw_rule_strategy=RawRuleStrategy(require_platform_in_path=True),
        factory=_sentinel_factory,
        post_load_validator=_azure_validator,
    ),
    "microsoft_xdr": PlatformDescriptor(
        toml_key="microsoft_xdr",
        env_var_groups=_AZURE_ENV_GROUPS,
        raw_rule_strategy=RawRuleStrategy(require_platform_in_path=False),
        factory=_xdr_factory,
        toml_key_resolver=_xdr_toml_key_resolver,
        post_load_transform=_xdr_post_load_transform,
        post_load_validator=_azure_validator,
    ),
    "esql": PlatformDescriptor(
        toml_key="elastic",
        env_var_groups=_ELASTIC_ENV_GROUPS,
        raw_rule_strategy=RawRuleStrategy(require_platform_in_path=False),
        factory=_elastic_factory,
    ),
    "eql": PlatformDescriptor(
        toml_key="elastic",
        env_var_groups=_ELASTIC_ENV_GROUPS,
        raw_rule_strategy=RawRuleStrategy(require_platform_in_path=False),
        factory=_elastic_factory,
    ),
}


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def get_platform(parameters: Any, export_config: dict, logger_param: dict, raw: bool = False):
    """Instantiate the correct platform from the registry.

    Parameters
    ----------
    parameters:
        The SimpleNamespace produced by build_parameters().
    export_config:
        The dict returned by load_platform_config().
    logger_param:
        The logger-parameter dict.
    raw:
        True when instantiating for the raw-rule code path.
        Only affects Elastic (sets ElasticPlatform.raw=True).
    """
    platform_name = parameters.platform
    if platform_name not in PLATFORM_REGISTRY:
        raise ValueError(f"Unknown platform: {platform_name}")

    # ElasticPlatform is the only class with a `raw` constructor parameter
    if raw and platform_name in ("esql", "eql"):
        from droid.platforms.elastic import ElasticPlatform
        return ElasticPlatform(export_config, logger_param, platform_name, raw=True)

    return PLATFORM_REGISTRY[platform_name].factory(export_config, logger_param, parameters)
