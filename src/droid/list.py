"""
Module to list items from the detection rules
"""
import yaml

from pathlib import Path
from sigma.plugins import InstalledSigmaPlugins
from droid.color import ColorLogger

def load_rule(parameters, rule_file, logger):
    """Load rule
    Load any detection rule in YAML format

    Returns:
        YAML object
    """
    logger.debug("processing rule {0}".format(rule_file))

    with open(rule_file, 'r') as stream:
        try:
            object = list(yaml.safe_load_all(stream))[0]
            return object
        except yaml.YAMLError as exc:
            print(exc)
            print("Error reading {0}".format(rule_file))
            error = True


def list_unique_keys(rule, unique_keys) -> None:
    """List unique detection keys
    List all the unique keys within the detection key in the Sigma rules.

    Returns:
        Unique keys list
    """
    detection_section = rule.get('detection', {})

    for key, value in detection_section.items():
        if key.startswith('selection'):
            if isinstance(value, list):
                for item in value:
                    for sub_key in item.keys():
                        if '|' in sub_key:
                            unique_keys.add(sub_key.split("|", 1)[0])
                        else:
                            unique_keys.add(sub_key)

            elif isinstance(value, dict):
                for sub_key in value.keys():
                    if '|' in sub_key:
                        unique_keys.add(sub_key.split("|", 1)[0])
                    else:
                        unique_keys.add(sub_key)

    # Convert the set to a list and print
    unique_keys_list = list(unique_keys)

    return unique_keys_list

def list_keys(parameters, logger_param) -> None:
    """List keys features
    Gather multiple listing mode such as:
        unique_fields: list all the unique fields in the Sigma detection section
        pipelines: list all the Sigma pipelines installed

    Output:
        Prints out the results.
    """

    logger = ColorLogger(__name__, **logger_param)

    if 'unique_fields' in parameters.list:
        path = Path(parameters.rules)
        unique_keys = set()
        if path.is_dir():
            for rule_file in path.rglob("*.y*ml"):
                rule = load_rule(parameters, rule_file)
                try:
                    unique_fields = list_unique_keys(rule, unique_keys)
                except AttributeError as e:
                    logger.warning(f"Couldn't list subkeys for {rule_file}, reasonL: {e}")
            print(*unique_fields, sep='\n')
        elif path.is_file():
            rule_file = path
            rule = load_rule(parameters, rule_file)
            unique_fields = list_unique_keys(rule, unique_keys)
            print(*unique_fields, sep='\n')
        else:
            print(f"The path {path} is neither a directory nor a file.")

    elif 'pipelines' in parameters.list:
        plugins = InstalledSigmaPlugins.autodiscover()
        pipeline_resolver = plugins.get_pipeline_resolver()
        pipeline_list = list(pipeline_resolver.pipelines.keys())
        print(*pipeline_list, sep='\n')