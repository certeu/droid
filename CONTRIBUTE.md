# Contributing to droid

Thank you for your interest in contributing. This guide covers setting up a development environment, running the tests, submitting a pull request, and adding support for a new platform.

## Development environment

droid needs Python 3.11.8 or later. Work in a virtual environment, install droid in editable mode with the test tools, then the pySigma backends of the platforms you work on:

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e . -r requirements-qa.txt
pip install pysigma-backend-splunk pysigma-backend-kusto pysigma-backend-elasticsearch
```

Every runtime dependency is pinned in both `requirements.txt` and `setup.cfg`: keep the two in sync when you change one. droid pins pySigma, so check that the backends you install keep that version (`pip show pysigma`): some backend releases require a newer pySigma and upgrade it silently.

## Running the tests

```sh
pytest tests/
```

The CI runs them in random order (`pytest --random-order`), so a test must never depend on another one having run before it.

A test must not reach a real platform: stub the HTTP calls and the SDK clients, credentials lookups included. Elasticsearch is the exception, with a few tests that run the converted queries on a live cluster when you point them at one, and skip otherwise:

```sh
docker run -d --name droid-es-test -p 127.0.0.1:9200:9200 \
  -e discovery.type=single-node -e xpack.security.enabled=false \
  docker.elastic.co/elasticsearch/elasticsearch:9.5.6
DROID_TEST_ELASTICSEARCH_URL=http://localhost:9200 pytest tests/test_elastic.py
```

### Writing tests

- Put each test next to the behaviour it covers, e.g. `tests/test_elastic.py` for the Elastic platform, and its fixtures (rules, pipelines, configurations) under `tests/files/`.
- Name a test after the behaviour it checks, e.g. `test_rule_kibana_refuses_to_show_is_an_error`, and say why in its docstring when it is not obvious.
- Write the test first for a bug: it must fail without your fix.
- Fixtures use fictional names only, from the world of the existing ones (Planet Express, Hermes, Leela, `planet-express.local`). Never put real organisations, people, hosts, addresses or credentials in tests, fixtures or commit messages.

## Submitting a pull request

1. Fork the repository and create a branch from `main`.
2. Make your changes, with their tests.
3. Run the test suite and make sure it passes.
4. Push your branch and open a pull request against `main`. Describe what the change does and why.

Keep pull requests small and scoped: a bug fix and a feature go in separate pull requests.

### Commit messages

Commits follow the [Conventional Commits](https://www.conventionalcommits.org/) style, with the platform as scope when the change is specific to one:

```
fix(elastic): check the integrity of every field export sets

Integrity only compared the query, the description and the enabled
state: a rule whose severity had been changed on Kibana passed the
check. ...
```

Use `feat` for a new capability, `fix` for a bug, `docs` for documentation and `build` for dependencies. The subject says what changes, the body says why.

## Adding a new platform

droid uses a registry to manage platforms. Adding one takes the following steps.

### Step 1. Create the platform class

Create a new file under `src/droid/platforms/`. Your class extends `AbstractPlatform` from `droid.abstracts` and implements its three methods.

```python
from droid.abstracts import AbstractPlatform
from droid.color import ColorLogger


class MyPlatform(AbstractPlatform):
    def __init__(self, parameters: dict, logger_param: dict) -> None:
        super().__init__(name="My Platform")
        self.logger = ColorLogger(__name__, **logger_param)
        self._parameters = parameters

    def create_rule(self, rule_content: dict, rule_converted: str, rule_file: str):
        """Create the rule, or update it when it already exists"""

    def get_rule(self, rule_content: dict, rule_converted: str, rule_file: str):
        """Return the deployed rule, or a falsy value when it does not exist"""

    def remove_rule(self, rule_content: dict, rule_converted: str, rule_file: str):
        """Delete the rule, a rule already gone included"""
```

Export calls `create_rule`, or `remove_rule` for a rule marked `removed`. A few rules make a platform behave like the existing ones:

- **Export is idempotent.** Compare the rule you would deploy with the deployed one, and only update it when they differ: running export twice over unchanged rules changes nothing.
- **Honour the custom fields** `disabled` and `removed`, and the `custom` fields your platform adds.
- **Errors are errors.** Raise when the platform refuses a call, with the reason it gave. Only report a rule as absent when the platform says it does not exist: a permission error is not an absent rule.
- **Credentials never come from the configuration file**, but from environment variables, see Step 2.

`src/droid/platforms/splunk.py` and `src/droid/platforms/elastic.py` are reference implementations.

### Step 2. Register the platform

Open `src/droid/platforms/registry.py` and add three things.

**A factory function** that imports and instantiates your class:

```python
def _myplatform_factory(config: dict, logger_param: dict, params):
    from droid.platforms.myplatform import MyPlatform
    return MyPlatform(config, logger_param)
```

**An environment variable group** that maps environment variables to configuration keys. Use the existing `_SPLUNK_ENV_GROUPS` or `_ELASTIC_ENV_GROUPS` as a guide:

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

Open `src/droid/config.py` and add your platform to the `Platform` enum:

```python
class Platform(str, Enum):
    ...
    myplatform = "myplatform"
```

droid looks the pySigma backend up by this name, so it must match the name the backend registers. When it cannot, map it in `Conversion` (`src/droid/convert.py`) the way `ms_cloud_kusto` maps both Microsoft platforms to the `kusto` backend.

### Step 4. Wire search and integrity

Search and integrity call the platform through functions of their own: add yours next to the existing ones.

- `src/droid/search.py`: a `search_rule_myplatform` function, dispatched from `search_rule`. It reports an error when the search fails, and a warning when it finds hits.
- `src/droid/integrity.py`: an `integrity_rule_myplatform` function, dispatched from `integrity_rule`. It compares every setting export deploys with the deployed rule, not only the query, and fails when it cannot read the platform.

### Step 5. Update dependencies

Add the Python packages your platform needs to `install_requires` in `setup.cfg` and to `requirements.txt`, pinned. Avoid new dependencies unless the platform strictly needs them.

### Step 6. Test it

Cover at least the conversion, the export (create, unchanged, update, disable, remove), the search and the integrity, with the platform calls stubbed. The Elastic tests in `tests/test_elastic.py` show the patterns.

### Step 7. Document the platform

Submit a pull request to [certeu/droid-docs](https://github.com/certeu/droid-docs) documenting the new platform: its TOML configuration and parameters, the environment variables of its credentials, the permissions droid needs on it, and its custom fields. Add it to the supported platforms of the README too.

## Code style

droid follows standard Python conventions. There is no enforced formatter: match the style of the surrounding code, its naming, its comments and its docstrings. Comments say why, not what.
