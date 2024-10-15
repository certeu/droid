"""
Module for Splunk
"""
import splunklib.client as client

from os import environ
from time import sleep
from droid.color import ColorLogger
from droid.abstracts import AbstractPlatform
from droid.platforms.common import get_pipeline_group_match
from splunklib.binding import AuthenticationError

class SplunkPlatform(AbstractPlatform):

    def __init__(self, parameters: dict, logger_param: dict) -> None:

        super().__init__(name="Splunk")

        self.logger = ColorLogger(__name__, **logger_param)
        self._parameters = parameters

        if 'url' not in self._parameters:
            raise Exception('SplunkPlatform: "url" parameter is required.')
        if 'port' not in self._parameters:
            raise Exception('SplunkPlatform: "port" parameter is required.')
        if 'user' not in self._parameters:
            raise Exception('SplunkPlatform: "user" parameter is required.')
        if 'password' not in self._parameters:
            raise Exception('SplunkPlatform: "password" parameter is required.')
        if 'earliest_time' not in self._parameters:
            raise Exception('SplunkPlatform: "earliest_time" parameter is required.')
        if 'latest_time' not in self._parameters:
            raise Exception('SplunkPlatform: "latest_time" parameter is required.')

        self._url = self._parameters['url']
        self._user = self._parameters['user']
        self._password = self._parameters['password']
        self._port = self._parameters['port']
        self._test_earliest_time = self._parameters['test_earliest_time']
        self._test_latest_time = self._parameters['test_latest_time']
        self._earliest_time = self._parameters['earliest_time']
        self._latest_time = self._parameters['latest_time']
        self._cron_schedule = self._parameters['cron_schedule']
        self._app = self._parameters['app']
        self._job_ttl = self._parameters['job_ttl']
        self._acl_update_owner = self._parameters['acl_update_owner']
        self._alert_expiration = self._parameters['alert_expiration']
        self._acl_update_perms_read = self._parameters['acl_update_perms_read']

        if 'suppress_fields_groups' in self._parameters['savedsearch_parameters']:
            self._suppress_fields_groups = self._parameters['savedsearch_parameters']['suppress_fields_groups']

    def run_splunk_search(self, rule_converted, rule_file) -> list:
        """
        :param access_token: JWT token to execute the request on the backend
        :return: List containing the Splunk result
        """
        try:
            service = client.connect(
                host= self._url,
                port=self._port,
                username=self._user,
                password=self._password,
                app=self._app)

        except AuthenticationError:
            self.logger.error("Login failed")
            raise

        if 'tstats' in rule_converted:
            rule_converted = f'{rule_converted}'
        else:
            rule_converted = f'search {rule_converted}'

        job = service.jobs.create(
            rule_converted,
            earliest_time=self._test_earliest_time,
            latest_time=self._test_latest_time,
            exec_mode="normal"
        )

        job.set_ttl(self._job_ttl)
        job.acl_update(sharing="app", owner=self._acl_update_owner, app=self._app, **{"perms.read": self._acl_update_perms_read})

        # A normal search returns the job's SID right away, so we need to poll for completion
        self.logger.info(f"Searching for rule {rule_file}")

        while True:
            while not job.is_ready():
                pass
            stats = {"isDone": job["isDone"],
                     "isFailed": job["isFailed"],
                    "doneProgress": float(job["doneProgress"])*100,
                    "scanCount": int(job["scanCount"]),
                    "eventCount": int(job["eventCount"]),
                    "resultCount": int(job["resultCount"]),
                    "sid": str(job["sid"])}

            status = ("\r%(doneProgress)03.1f%%   %(scanCount)d scanned   "
                    "%(eventCount)d matched   %(resultCount)d results for rule: " + f'{rule_file}') % stats

            #sys.stdout.write(status)
            #sys.stdout.flush()
            if stats["isDone"] == "1":
                break
            sleep(2)

        # Get the results and display them

        job_url = f'https://{self._url}/en-US/app/{self._app}/search?sid=' + stats["sid"]

        stats["jobUrl"] = job_url

        if stats["isFailed"] == "1":
            self.logger.error(f"Failed to search the rule: " + job_url)
            raise
        else:
            return stats

    def search_savedsearch(self, rule_content: dict):

        alert_name = rule_content["title"]

        service = client.connect(
            host= self._url,
            port=self._port,
            username=self._user,
            password=self._password,
            app=self._app)

        try:
            exists = service.saved_searches[alert_name]
            return exists
        except:
            return False

    def remove_rule(self, rule_content: dict, rule_converted: str, rule_file: str):

        alert_name = rule_content["title"]

        service = client.connect(
            host= self._url,
            port=self._port,
            username=self._user,
            password=self._password,
            app=self._app)

        if self.search_savedsearch(rule_content): # If the rule already exists
            saved_search = service.saved_searches.delete(alert_name)
            self.logger.info(f"Saved search for rule {rule_file} deleted", extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content})
        else:
            self.logger.info(f"Saved search for rule {rule_file} already deleted", extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content})

    def get_rule(self, rule_content: dict, rule_converted: str, rule_file: str):

        alert_name = rule_content["title"]

        service = client.connect(
            host= self._url,
            port=self._port,
            username=self._user,
            password=self._password,
            app=self._app)

        if self.search_savedsearch(rule_content): # If the rule already exists
            return self.search_savedsearch(rule_content)
        else:
            return False

    def create_rule(self, rule_content: dict, rule_converted: str, rule_file: str):
        earliest_time = self._earliest_time
        latest_time = self._latest_time
        cron_schedule = self._cron_schedule
        alert_expiration = self._alert_expiration
        alert_name = rule_content["title"]
        alert_description = rule_content["description"]

        service = client.connect(
            host=self._url,
            port=self._port,
            username=self._user,
            password=self._password,
            app=self._app
        )

        alert_config = {
            "name": alert_name,
            "description": alert_description,
            "search": rule_converted,
            "cron_schedule": cron_schedule,
            "dispatch.earliest_time": earliest_time,
            "dispatch.latest_time": latest_time,
            "is_scheduled": True,
            "disabled": False,
            "alert.expires": alert_expiration,
            "is_visible": True
        }

        # Add actions to alert_config from droid_config.toml

        # Applying global config
        if rule_content.get('custom', {}).get('disabled') is True:
            alert_config["disabled"] = True
            self.logger.info(f"Successfully disabled the rule {rule_file}",
                            extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content})

        if 'savedsearch_parameters' in self._parameters:
            for item in self._parameters['savedsearch_parameters']:
                alert_config[item] = self._parameters['savedsearch_parameters'][item]

        if 'action' in self._parameters:
            for item in self._parameters['action']:
                alert_config[item] = self._parameters['action'][item]

        # Applying general config if override in custom
        if 'custom' in rule_content:
            custom_config = rule_content['custom']
            if 'earliest_time' in custom_config:
                alert_config['dispatch.earliest_time'] = custom_config["earliest_time"]
            if 'latest_time' in custom_config:
                alert_config['dispatch.latest_time'] = custom_config["latest_time"]
            if 'cron_schedule' in custom_config:
                alert_config['cron_schedule'] = custom_config["cron_schedule"]

        if 'suppress_fields_groups' in self._parameters['savedsearch_parameters']:
            suppress_config_group = get_pipeline_group_match(rule_content, self._suppress_fields_groups)
            if suppress_config_group:
                self.logger.debug(f"Applying the suppress fields from group {suppress_config_group}")
                alert_config['alert.suppress.fields'] = self._suppress_fields_groups[suppress_config_group]['alert.suppress.fields']
            alert_config.pop('suppress_fields_groups')

        if 'alert.suppress.fields' in rule_content.get('custom', {}):
            alert_config['alert.suppress.fields'] = rule_content['custom']["alert.suppress.fields"]

        if 'alert.suppress.period' in rule_content.get('custom', {}):
            alert_config['alert.suppress.period'] = rule_content['custom']["alert.suppress.period"]

        if 'alert.suppress' in rule_content.get('custom', {}):
            alert_config['alert.suppress'] = rule_content['custom']["alert.suppress"]
            if alert_config['alert.suppress'] == "0":
                alert_config.pop('alert.suppress.period', None)
                alert_config.pop('alert.suppress.fields', None)
            elif alert_config['alert.suppress'] == "1":
                pass
            else:
                self.logger.error('Custom key alert.suppress must be either "0" or "1"')
                raise ValueError('Custom key alert.suppress must be either "0" or "1"')

        if 'alert.digest_mode' in rule_content.get('custom', {}):
            alert_config['alert.digest_mode'] = rule_content['custom']["alert.digest_mode"]
            if alert_config['alert.digest_mode'] == "0":
                pass
            elif alert_config['alert.digest_mode'] == "1":
                pass
            else:
                self.logger.error('Custom key alert.digest_mode must be either "0" or "1"')
                raise ValueError('Custom key alert.digest_mode must be either "0" or "1"')

        # Applying trigger actions config if override in custom
        if 'actions' in rule_content.get('custom', {}):
            alert_config['actions'] = rule_content['custom']["actions"]

            if 'action.webhook.param.url' in rule_content['custom']:
                webhook_url = rule_content['custom']['action.webhook.param.url']
                if str(webhook_url).startswith("$"):
                    env = webhook_url[1:]
                    if not environ.get(env):
                        self.logger.error(f"Could not find {env} in env")
                        raise EnvironmentError(f"Could not find {env} in env")
                    alert_config['action.webhook.param.url'] = environ.get(env)
                else:
                    alert_config['action.webhook.param.url'] = webhook_url

        # Create or update the saved search
        if self.search_savedsearch(rule_content):  # If the rule already exists
            saved_search = self.search_savedsearch(rule_content)
            del alert_config['name']  # Remove name as it can't be updated
            try:
                saved_search.update(**alert_config).refresh()
                self.logger.info(f"Saved search for rule {rule_file} modified",
                                extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content})
            except Exception as e:
                self.logger.error(f"Could not modify the saved search for rule {rule_file} created - error: {e}",
                                extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content, "error": e})
                raise
        else:
            try:
                saved_search = service.saved_searches.create(**alert_config)
                self.logger.info(f"Saved search for rule {rule_file} created",
                                extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content})
            except Exception as e:
                self.logger.error(f"Could not create the saved search for rule {rule_file}: {e}",
                                extra={"rule_file": rule_file, "rule_converted": rule_converted, "rule_content": rule_content, "error": e})
                raise


