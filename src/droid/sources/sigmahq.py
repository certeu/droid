"""
Module handling the update of the rules coming from SigmaHQ
"""

import requests
import re
import yaml
import shutil
import requests

from zipfile import ZipFile
from ruamel.yaml import YAML
from droid.color import ColorLogger
from pathlib import Path

yaml = YAML()

yaml.preserve_quotes = True

def load_rule(parameters, rule_file, logger):

    logger.debug("processing rule {0}".format(rule_file))

    with open(rule_file, 'r') as stream:
        try:
            object = list(yaml.load_all(stream))[0]
        except Exception as e:
            logger.error(f"Error while loading the rule {rule_file} - reason: {e}")
            error = True

    return object

def update_with_tracking(existing_data, new_data):
    """Update with tracking
    Function to update existing rules
    """
    updated_keys = []

    for key, value in new_data.items():
        if key not in existing_data or existing_data[key] != value:
            updated_keys.append(key)
            existing_data[key] = value

def update_rule_content(parameters, new_data, target_file_path, logger):
    """Update rule content
    Function used to update a Sigma rule
    """
    with open(target_file_path, 'r') as f:
        try:
            existing_data = yaml.load(f) or {}
        except Exception as e:
            logger.error(f"Error while loading the rule - reason: {e}")
            error = True
    try:
        updated_keys = update_with_tracking(existing_data, new_data)
        if updated_keys != []:
            logger.info(f"Updated rule {existing_data['title']} from file {target_file_path}")

        logger.debug(f"Updated data {existing_data} in {target_file_path}")

        with open(target_file_path, 'w') as f:
            yaml.dump(existing_data, f)

    except Exception as e:
        logger.error(f"Error while updating the rule - reason: {e}")
        error = True

def download_sigma_core(logger):
    """SigmaHQ/Core
    Function used to download SigmaHQ/Core rules
    """
    latest_release_url = f"https://api.github.com/repos/SigmaHQ/sigma/releases/latest"

    tmp_directory = Path("tmp/")

    tmp_directory.mkdir(parents=True, exist_ok=True)

    response = requests.get(latest_release_url)
    if response.status_code != 200:
        logger.error(f"(SIGMAHQ/Core) Failed to get latest release info: {response.status_code}")
        exit(1)

    release_info = response.json()

    asset_url = None

    for asset in release_info['assets']:
        if re.match('sigma_core.zip', asset['name']):
            asset_url = asset['browser_download_url']
            break

    if asset_url is None:
        logger.error("(SIGMAHQ/Core) No matching asset found in the latest release.")
        exit(1)

    response = requests.get(asset_url)
    if response.status_code != 200:
        logger.error(f"(SIGMAHQ/Core) Failed to download asset: {response.status_code}")
        exit(1)

    asset_name = asset_url.split('/')[-1]
    file_path = tmp_directory / asset_name
    with open(file_path, 'wb') as f:
        f.write(response.content)

    logger.info(f"(SIGMAHQ/Core) Successfully downloaded {asset_name}")

    return asset_name


def update_sigmahq_core(parameters, logger_param):
    """Update rules
    """
    # Sigma Core

    logger = ColorLogger(__name__, **logger_param)

    rules_zip = download_sigma_core(logger)
    with ZipFile(f"tmp/{rules_zip}", 'r') as zip_ref:
        zip_ref.extractall("tmp/")
        zip_ref.close()

    source_path = Path(f"tmp/rules/")
    target_path = Path(parameters.rules)

    unmatched_files = []

    for rule_file in source_path.rglob("*.y*ml"):

        rule_filename = rule_file.name
        matching_files = list(target_path.rglob(rule_filename))
        target_file_path = target_path / rule_filename

        if len(matching_files) != 0:
            new_data = load_rule(parameters, rule_file)
            for target_file_path in matching_files:
                update_rule_content(parameters, new_data, target_file_path, logger)
        else:
            new_rule = str(rule_file).replace(f"{source_path}", f"{target_path}")
            rule = load_rule(parameters, rule_file, logger)
            rule_name = rule['title']

            logger.info(f"New rule! Adding: {rule_name} from {new_rule}")

            new_rule_path = Path(new_rule)
            new_rule_path.parent.mkdir(parents=True, exist_ok=True)

            shutil.copy2(rule_file, new_rule)
            unmatched_files.append(rule_filename)

    target_files = set([file.name for file in target_path.rglob("*.y*ml")])
    zip_files = set([file.name for file in source_path.rglob("*.y*ml")])

    rules_deleted = list(target_files - zip_files - set(unmatched_files))

    if rules_deleted:
        for file_name in rules_deleted:
            file_path = list(target_path.rglob(file_name))[0]
            logger.warning(f"The following rule was not included in the latest Sigma Core release: {file_path}")