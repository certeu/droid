"""
Module holding common functions for the platforms
"""

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