"""
Module holding common functions for the platforms
"""

from os import environ

def get_token_hook_headers():
    """Build the headers sent to the Azure token hook

    DROID_AZURE_TOKEN_HEADER and DROID_AZURE_TOKEN_HEADER_VALUE define a custom
    header taking precedence over the default X-API-Key header sourced from
    DROID_AZURE_TOKEN_X_API_KEY.

    Return: a dict with the headers to send to the hook
    """

    header_name = environ.get('DROID_AZURE_TOKEN_HEADER')
    header_value = environ.get('DROID_AZURE_TOKEN_HEADER_VALUE')

    if header_name and header_value:
        return {header_name: header_value}

    if header_name:
        raise ValueError("DROID_AZURE_TOKEN_HEADER is set but DROID_AZURE_TOKEN_HEADER_VALUE is missing")

    if header_value:
        raise ValueError("DROID_AZURE_TOKEN_HEADER_VALUE is set but DROID_AZURE_TOKEN_HEADER is missing")

    api_key = environ.get('DROID_AZURE_TOKEN_X_API_KEY')

    if api_key:
        return {'X-API-Key': api_key}

    return {}

def get_error_message(response):
    """Extract the error message out of a platform API response

    The response is the already decoded body. It may be None when the request
    could not be performed at all, or may not carry the expected error
    structure, hence the fallbacks.

    Return: a str with the error message
    """

    if isinstance(response, dict):
        error = response.get('error')
        if isinstance(error, dict):
            return error.get('message', str(error))
        if error:
            return str(error)

    if response is None:
        return "No response from the platform"

    return str(response)

def get_pipeline_group_match(rule_content: dict, fields: dict):
    """Retrieve the config group name based on a dict

    Return: a str with the pipeline config group
    """

    sigma_logsource_fields = ['category', 'product', 'service']
    rule_logsource = {}

    for key, value in rule_content['logsource'].items():
        if key in sigma_logsource_fields:
            rule_logsource[key] = value

    for key, value in fields.items():
        value = {k: v for k, v in value.items()  if k in sigma_logsource_fields}
        if value == rule_logsource:
            group_match = key
            break
        else:
            group_match = None

    return group_match