"""
Module to convert the Sigma rules
"""
import yaml

from pathlib import Path
from sigma.plugins import InstalledSigmaPlugins
from sigma.conversion.base import Backend, SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from droid.search import search_rule
from droid.export import export_rule
from droid.integrity import integrity_rule
from droid.platforms.splunk import SplunkPlatform
from droid.platforms.sentinel import SentinelPlatform
from droid.platforms.elastic import ElasticPlatform
from droid.platforms.ms_xdr import MicrosoftXDRPlatform
from droid.color import ColorLogger

class Conversion:
    """Base class handling the conversion

    Args:
        parameters(dict)
    """
    def __init__(self, parameters: dict, base_config, platform_name, logger_param) -> None:
        self.logger = ColorLogger(__name__, **logger_param)
        self._parameters = parameters["pipelines"]
        self._filters_directory = base_config.get("sigma_filters_directory", None)
        self._platform_name = platform_name

    def get_pipeline_config_group(self, rule_content):
        """Retrieve the logsource config group name
        Search a match in the configuration in platforms.x.pipelines and fetch the pipeline group name

        Return: a str with the pipeline config group
        """

        sigma_logsource_fields = ["category", "product", "service"]
        rule_logsource = {}

        for key, value in rule_content["logsource"].items():
            if key in sigma_logsource_fields:
                rule_logsource[key] = value

        for key, value in self._parameters.items():
            value = {k: v for k, v in value.items()  if k in sigma_logsource_fields}
            if value == rule_logsource:
                self.logger.info(f"Pipeline config found: {key}")
                group_match = key
                break
            else:
                group_match = None

        return group_match

    def ms_cloud_kusto(self) -> str | None:
        """Function to select the right Kusto backend

        Return:
            "kusto" if one of the mscloud platforms or None
        """
        return "kusto" if self._platform_name in ["microsoft_sentinel", "microsoft_xdr"] else None

    def init_sigma_filters(self, rule_file) -> None:
        """Function to load Sigma filters
        Args:
            filter_path
        """
        filters = SigmaCollection.load_ruleset(
            [
                Path(self._filters_directory),
                Path(rule_file)
            ]
        )

        return filters

    def init_sigma_rule(self, rule_file) -> None:
        """Function to load a sigma rule

        Args:
            rule
        """
        with open(rule_file, "r", encoding="utf-8") as file:
            if self._filters_directory:
                sigma_rule = self.init_sigma_filters(rule_file)
            else:
                sigma_rule = SigmaCollection.from_yaml(file)

        return sigma_rule

    def convert_rule(self, rule_content, rule_file, platform):

        plugins = InstalledSigmaPlugins.autodiscover()
        backends = plugins.backends
        pipeline_resolver = plugins.get_pipeline_resolver()
        pipeline_config_group = self.get_pipeline_config_group(rule_content)

        backend_name = self.ms_cloud_kusto() or self._platform_name
        if backend_name not in backends:
            self.logger.error(f"{backend_name} backend not installed.")
            exit(1)

        # Pipeline config

        if pipeline_config_group:
            rule_supported = True
            pipeline_config = self._parameters[pipeline_config_group]["pipelines"]
            # Format
            if "format" in self._parameters[pipeline_config_group]:
                self._format = self._parameters[pipeline_config_group]["format"]
            else:
                self._format = "default"
        else:
            rule_supported = False

        if rule_supported:
            backend_class = backends[self.ms_cloud_kusto() or self._platform_name]
            if pipeline_config:
                pipeline = pipeline_resolver.resolve(pipeline_config)
            else:
                pipeline = None
            backend: Backend = backend_class(processing_pipeline=pipeline)
            sigma_rule = self.init_sigma_rule(rule_file)
            rule_converted = backend.convert(sigma_rule, self._format)[0]
            # For esql and eql backend only
            if isinstance(platform, ElasticPlatform):
                platform.get_index_name(pipeline, rule_content)
            self.logger.info(f"Successfully convert the rule {rule_file}", extra={"rule_file": rule_file, "rule_content": rule_content, "rule_format": self._format, "rule_converted": rule_converted})
            return rule_converted
        else:
            self.logger.warning(f"Rule not supported: {rule_file}", extra={"rule_file": rule_file, "rule_content": rule_content})

def load_rule(rule_file):

    with open(rule_file, "r", encoding="utf-8") as stream:
        try:
            object = list(yaml.safe_load_all(stream))[0]
            if "fields" in object:
                object.pop("fields")
                # Here we remove the fields to avoid Sigma to arbitrary
                # convert the rule to {{ query }} | table field1,field2
                # https://github.com/SigmaHQ/pySigma-backend-splunk/issues/27
            return object
        except yaml.YAMLError as exc:
            print(exc)
            print("Error reading {0}".format(rule_file))
            error = True
            return error

def convert_sigma_rule(rule_file, parameters, logger, sigma_objects, target, platform, error, search_warning, rules, logger_param):

    logger.debug("processing rule {0}".format(rule_file))

    rule_content = load_rule(rule_file)
    sigma_objects[rule_content["title"]] = rule_content
    error, search_warning = convert_sigma(parameters, logger, rule_content, rule_file, target, platform, error, search_warning, rules, logger_param)
    return error, search_warning

def convert_rules(parameters, droid_config, base_config, logger_param):

    logger = ColorLogger(__name__, **logger_param)

    error = False
    search_warning = False

    sigma_objects = {}

    path = Path(parameters.rules)

    rules = []

    if parameters.platform and parameters.convert:
        platform_name = parameters.platform
        target = Conversion(droid_config, base_config, platform_name, logger_param)
        platform = None

    if parameters.platform and (parameters.search or parameters.export or parameters.integrity):
        platform_name = parameters.platform
        target = Conversion(droid_config, base_config, platform_name, logger_param)
        if platform_name == "splunk":
            platform = SplunkPlatform(droid_config, logger_param)
        elif "esql" in platform_name:
            platform = ElasticPlatform(droid_config, logger_param, "esql", raw=False)
        elif "eql" in platform_name:
            platform = ElasticPlatform(droid_config, logger_param, "eql", raw=False)
        elif "microsoft_sentinel" in platform_name and parameters.mssp:
            platform = SentinelPlatform(droid_config, logger_param, export_mssp=True)
        elif "microsoft_sentinel" in platform_name:
            platform = SentinelPlatform(droid_config, logger_param, export_mssp=False)
        elif "microsoft_xdr" in platform_name and parameters.sentinel_xdr and parameters.mssp:
            platform = SentinelPlatform(droid_config, logger_param, export_mssp=True)
        elif "microsoft_xdr" in platform_name and parameters.sentinel_xdr:
            platform = SentinelPlatform(droid_config, logger_param, export_mssp=False)
        elif "microsoft_xdr" in platform_name and parameters.mssp:
            platform = MicrosoftXDRPlatform(droid_config, logger_param, export_mssp=True)
        elif "microsoft_xdr" in platform_name:
            platform = MicrosoftXDRPlatform(droid_config, logger_param, export_mssp=False)

    if path.is_dir():
        error_i = False
        search_warning_i = False
        for rule_file in path.rglob("*.y*ml"):
            error, search_warning = convert_sigma_rule(rule_file, parameters, logger, sigma_objects, target, platform, error, search_warning, rules, logger_param)
            if parameters.module:
                rules.append(error)
            if error:
                error_i = True
            if search_warning:
                search_warning_i = True
        if error_i:
            error = True
            return error, search_warning
        if search_warning_i:
            search_warning = True
            return error, search_warning

    elif path.is_file():
        error, search_warning = convert_sigma_rule(path, parameters, logger, sigma_objects, target, platform, error, search_warning, rules, logger_param)
        if parameters.module:
            rules.append(error)
    else:
        print(f"The path {path} is neither a directory nor a file.")

    if parameters.search:
        return error, search_warning

    elif parameters.module:
        # Remove None values
        rules_list = []
        for val in rules:
            if val != None :
                rules_list.append(val)
        return rules_list

    elif parameters.export:
        return error
    elif parameters.integrity:
        return error
    else:
        return error, search_warning


def convert_sigma(
        parameters, logger, rule_content,
        rule_file, target, platform,
        error, search_warning, rules,
        logger_param):

    try:
        rule_converted = target.convert_rule(rule_content, rule_file, platform)

        logger.debug(f"Rule {rule_file} converted into: {rule_converted}", extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content})

    except SigmaFeatureNotSupportedByBackendError as e:
        logger.warning(f"Sigma Backend Error: {rule_file} - error: {e}", extra={"rule_file": rule_file, "error": e, "rule_content": rule_content})
        error = False
        return error, search_warning

    except SigmaTransformationError as e:
        logger.error(f"Sigma Transformation error: {rule_file} - error: {e}", extra={"rule_file": rule_file, "error": e, "rule_content": rule_content})
        error = True
        return error, search_warning
    except NotImplementedError as e:
        logger.error(f"Sigma Transformation error: {rule_file} - error: {e}", extra={"rule_file": rule_file, "error": e, "rule_content": rule_content})
        error = True
        return error, search_warning
    except Exception as e:
            logger.error(f"Fatal error when compiling the rule {rule_file} - verify the backend {e} is installed")
            error = True
            pass

    if parameters.export and parameters.search and rule_converted:
        try:
            error, search_warning = search_rule(parameters, rule_content, rule_converted, platform, rule_file, error, search_warning, logger_param)
        except:
            logger.error(f"Could not export the rule {rule_file} since the search ran into error.", extra={"rule_file": rule_file, "error": e, "rule_content": rule_content})

        if not error:
            error = False
            error = export_rule(parameters, rule_content, rule_converted, platform, rule_file, error, logger_param)

        return error, search_warning

    elif parameters.search and rule_converted:
        error, search_warning = search_rule(parameters, rule_content, rule_converted, platform, rule_file, error, search_warning, logger_param)
        return error, search_warning

    elif parameters.export and rule_converted:
        error = export_rule(parameters, rule_content, rule_converted, platform, rule_file, error, logger_param)
        return error, search_warning

    elif parameters.integrity and rule_converted:
        error = integrity_rule(parameters, rule_converted, rule_content, platform, rule_file, error, logger_param)
        return error, search_warning

    elif parameters.module:
        rules.append(rule_converted)

    else:
        return error, search_warning