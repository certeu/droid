"""
Module to validate the detection rules
"""
import yaml

from pathlib import Path
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.plugins import InstalledSigmaPlugins
from sigma.exceptions import SigmaDetectionError
from sigma.exceptions import SigmaConditionError
from droid.color import ColorLogger

class SigmaValidation:

    def __init__(self, base_config, logger_param) -> None:
        self._parameters = base_config
        self._validation_config_path = self._parameters["sigma_validation_config"]

        self.logger = ColorLogger(__name__, **logger_param)

        self.logger.debug("Initializing droid.validate.SigmaValidation")

    def validators(self) -> None:
        return InstalledSigmaPlugins.autodiscover().validators

    def init_validator(self) -> None:
        with open(self._validation_config_path) as validation_config:
            self._rule_validator = SigmaValidator.from_yaml(validation_config.read(), self.validators())

    def init_sigma_rule(self, rule, rule_file) -> None:
        try:
            sigma_rule = SigmaRule.from_dict(rule)
            return sigma_rule
        except SigmaDetectionError as e:
            self.logger.error(f"Error in Sigma detection: {e}")
            exit(1)
        except SigmaConditionError as e:
            self.logger.error(f"Error in Sigma condition: {e}")
            exit(1)
        except Exception as e:
            self.logger.error(f"Error when loading rule {rule_file}: {e}")

    def validate_rule(self, rule, rule_file):
        try:
            issues = self._rule_validator.validate_rule(self.init_sigma_rule(rule, rule_file))
            return issues
        except SigmaConditionError as e:
            self.logger.error(f"Error in Sigma condition for rule {rule_file}: {e}")
            exit(1)

def load_rule(parameters, logger, rule_file):

    logger.debug("processing rule {0}".format(rule_file), extra={"rule_file": rule_file})

    with open(rule_file, 'r') as stream:
        try:
            object = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            print("Error reading {0}".format(rule_file))
            error = True

    return object

def validate_rules(parameters, return_objects, base_config, logger_param) -> None:

    logger = ColorLogger(__name__, **logger_param)

    error = False

    rule_uuids = []

    objects = {}

    path = Path(parameters.rules)

    validation = SigmaValidation(base_config, logger_param)

    validation.init_validator() # First, initiate the validator class

    if path.is_dir():
        for rule_file in path.rglob("*.y*ml"):
            object = load_rule(parameters, logger, rule_file)
            objects[object['title']] = object
            error = validate_sigma_content(object, parameters, logger, validation, rule_file, rule_uuids, error)
    elif path.is_file():
            rule_file = path
            object = load_rule(parameters, logger, rule_file)
            objects[object['title']] = object
            error = validate_sigma_content(object, parameters, logger, validation, rule_file, rule_uuids, error)
    else:
        print(f"The path {path} is neither a directory nor a file.")

    # validate
    if return_objects:
        return error, objects
    else:
        return error


def validate_sigma_content(rule, parameters, logger, validation, rule_file, rule_uuids, error):

    errors = []

    if 'correlation' in rule:
        # Ignoring correlation rules in validation
        logger.info(f"Ignoring validation for correlation rule: {rule_file}")
        return error

    sigma_issues = validation.validate_rule(rule, rule_file)

    if sigma_issues:
        errors.append(sigma_issues)

        error = True

        for issue in sigma_issues:
            print(f"{issue.description} - severity {issue.severity.name} at:\n\t {rule_file}")
            logger.debug(f"Issue for rule {rule_file}: {issue}")

        return errors

    if rule['id'] in rule_uuids:
        duplicate_uuids = f"Duplicate UUID found: {rule['id']} in rule {rule_file}"
        print(duplicate_uuids)
        logger.debug(f"Issue for rule {rule_file}: {duplicate_uuids}")
        errors.append(duplicate_uuids)
        return errors
    else:
        rule_uuids.append(rule['id'])

    return error


