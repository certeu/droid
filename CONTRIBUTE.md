# Contributing to droid

Thank you for your interest in contributing. This document covers how to submit a pull request and how to add support for a new platform.

## Submitting a Pull Request

1. Fork the repository and create a branch from `main`.
2. Install the project in editable mode with its dependencies:

   ```
   pip install -e ".[dev]"
   ```

3. Make your changes. Keep commits focused and descriptive.
4. Run the test suite and ensure it passes:

   ```
   pytest tests/
   ```
   
5. Push your branch and open a pull request against `main`. Describe what the change does and why.

Keep pull requests small and scoped. If you are addressing a bug and a feature at the same time, split them into separate PRs.

## Adding a New Platform

Droid uses a registry pattern to manage platforms. Adding a new platform involves the following steps.

### Step 1. Create the platform class

Create a new file under `src/droid/platforms/`. Your class must extend `AbstractPlatform` from `droid.abstracts` and implement the three required methods.

```python
from droid.abstracts import AbstractPlatform
from droid.color import ColorLogger

class MyPlatform(AbstractPlatform):
    def __init__(self, parameters: dict, logger_param: dict) -> None:
        super().__init__(name="My Platform")
        self.logger = ColorLogger(__name__, **logger_param)
        self._parameters = parameters

    def create_rule(self, rule_content: dict, rule_converted: str, rule_file: str):
        ...

    def get_rule(self, rule_content: dict, rule_converted: str, rule_file: str):
        ...

    def remove_rule(self, rule_content: dict, rule_converted: str, rule_file: str):
        ...
```

Look at `src/droid/platforms/splunk.py` or `src/droid/platforms/elastic.py` for reference implementations.

### Step 2. Register the platform

Open `src/droid/platforms/registry.py` and add three things.

**A factory function** that imports and instantiates your class:

```python
def _myplatform_factory(config: dict, logger_param: dict, params):
    from droid.platforms.myplatform import MyPlatform
    return MyPlatform(config, logger_param)
```

**An environment variable group** that maps environment variables to config keys. Use the existing `_SPLUNK_ENV_GROUPS` or `_ELASTIC_ENV_GROUPS` definitions as a guide:

```python
_MYPLATFORM_ENV_GROUPS: list[EnvVarGroup] = [
    EnvVarGroup(
        condition=_is_deploy_op,
        mappings=[
            EnvVarMapping("DROID_MYPLATFORM_URL",      "url",      required=True),
            EnvVarMapping("DROID_MYPLATFORM_API_KEY",  "api_key",  required=True),
        ],
    ),
]
```

**An entry in `PLATFORM_REGISTRY`**:

```python
"myplatform": PlatformDescriptor(
    toml_key="myplatform",
    env_var_groups=_MYPLATFORM_ENV_GROUPS,
    raw_rule_strategy=RawRuleStrategy(
        require_platform_in_path=False,
        never_raw=False,
    ),
    factory=_myplatform_factory,
),
```

Set `never_raw=True` if the platform does not support raw (non-Sigma) rules.

### Step 3. Add the platform to the enum

Open `src/droid/config.py` and add your platform name to the `Platform` enum:

```python
class Platform(str, Enum):
    ...
    myplatform = "myplatform"
```

Note, if your platform requires a pySigma backend, the value of the enum must match the backend name (.e.g. `kusto` for `microsoft_xdr`)

### Step 4. Update dependencies

If your platform requires additional Python packages, add them to the appropriate extras section in `setup.cfg`. Follow the pattern used by the existing platforms (for example `azure` or `elastic` extras).

### Step 5. Document the platform

Submit a pull request to [certeu/droid-docs](https://github.com/certeu/droid-docs) documenting the new platform. This should cover the expected TOML configuration, available parameters, and which environment variables are used for credentials.

## Code Style

Droid uses standard Python conventions. There is no enforced formatter at this time, but please match the style of the surrounding code. Avoid introducing dependencies unless they are strictly necessary for the platform you are adding.
