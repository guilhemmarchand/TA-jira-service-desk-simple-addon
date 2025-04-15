#!/usr/bin/env python
# coding=utf-8

import sys
import os
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import logging
from logging.handlers import RotatingFileHandler

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = RotatingFileHandler(
    f"{splunkhome}/var/log/splunk/ta_jira_jirafill.log",
    mode="a",
    maxBytes=10000000,
    backupCount=1,
)

formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)  # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

sys.path.append(
    os.path.join(splunkhome, "etc", "apps", "TA-jira-service-desk-simple-addon", "lib")
)

from splunklib.searchcommands import (
    dispatch,
    GeneratingCommand,
    Configuration,
    Option,
    validators,
)

# import least privileges access libs
from ta_jira_libs import (
    jira_get_conf,
    jira_get_accounts,
    jira_get_account,
    jira_build_headers,
    jira_test_connectivity,
    jira_handle_ssl_certificate,
)


@Configuration(distributed=False)
class GenerateTextCommand(GeneratingCommand):

    account = Option(
        doc="""
        **Syntax:** **account=****
        **Description:** Optional, account to be used.""",
        require=False,
        default="_all",
        validate=validators.Match("account", r"^.*$"),
    )

    opt = Option(
        doc="""
        **Syntax:** **opt=****
        **Description:** Optional, action to be performed.""",
        require=False,
        default=0,
        validate=validators.Match("opt", r"^(0|1|2|3|4)$"),
    )

    def jira_url(self, url, endpoint):
        # For Splunk Cloud vetting, the URL must start with https://
        if not url.startswith("https://"):
            return f"https://{url}/rest/api/latest/{endpoint}"
        else:
            return f"{url}/rest/api/latest/{endpoint}"

    def get_jira_info(
        self,
        jira_url,
        jira_auth_mode,
        jira_username,
        jira_password,
        jira_ssl_certificate_path,
        jira_ssl_certificate_pem,
        proxy_dict,
        timeout,
    ):
        """
        Get JIRA information based on the option
        Option 0: Test connectivity
        Option 1: Get projects
        Option 2: Get issue types
        Option 3: Get priorities
        Option 4: Get statuses
        Option 5: Get resolutions
        """
        # Build the authentication header for JIRA
        jira_headers = jira_build_headers(jira_auth_mode, jira_username, jira_password)

        # Handle SSL certificate configuration
        ssl_config, temp_cert_file = jira_handle_ssl_certificate(
            jira_ssl_certificate_path, jira_ssl_certificate_pem
        )

        # Get the information based on the option
        if int(self.opt) == 0:
            # Test connectivity
            response = requests.get(
                url=f"{jira_url}/rest/api/latest/myself",
                headers=jira_headers,
                verify=ssl_config,
                proxies=proxy_dict,
                timeout=timeout,
            )
            response.raise_for_status()
            return response.json()

        elif int(self.opt) == 1:
            # Get all projects
            response = requests.get(
                url=f"{jira_url}/rest/api/latest/project",
                headers=jira_headers,
                verify=ssl_config,
                proxies=proxy_dict,
                timeout=timeout,
            )
            response.raise_for_status()
            return response.json()

        elif int(self.opt) == 2:
            # Get all issue types
            response = requests.get(
                url=f"{jira_url}/rest/api/latest/issuetype",
                headers=jira_headers,
                verify=ssl_config,
                proxies=proxy_dict,
                timeout=timeout,
            )
            response.raise_for_status()
            return response.json()

        elif int(self.opt) == 3:
            # Get all priorities
            response = requests.get(
                url=f"{jira_url}/rest/api/latest/priority",
                headers=jira_headers,
                verify=ssl_config,
                proxies=proxy_dict,
                timeout=timeout,
            )
            response.raise_for_status()
            return response.json()

        elif int(self.opt) == 4:
            # Get all statuses
            response = requests.get(
                url=f"{jira_url}/rest/api/latest/status",
                headers=jira_headers,
                verify=ssl_config,
                proxies=proxy_dict,
                timeout=timeout,
            )
            response.raise_for_status()
            return response.json()

        elif int(self.opt) == 5:
            # Get all resolutions
            response = requests.get(
                url=f"{jira_url}/rest/api/latest/resolution",
                headers=jira_headers,
                verify=ssl_config,
                proxies=proxy_dict,
                timeout=timeout,
            )
            response.raise_for_status()
            return response.json()

        else:
            raise Exception(f"Invalid option: {self.opt}")

    def generate(self):
        """
        Generate the results
        """
        # get conf
        jira_conf = jira_get_conf(
            self._metadata.searchinfo.session_key, self._metadata.searchinfo.splunkd_uri
        )

        # set loglevel
        log.setLevel(jira_conf["logging"]["loglevel"])

        # global configuration
        proxy_conf = jira_conf["proxy"]
        proxy_dict = proxy_conf.get("proxy_dict", {})

        # set timeout
        timeout = int(jira_conf["advanced_configuration"].get("timeout", 120))

        # get all acounts
        accounts_dict = jira_get_accounts(
            self._metadata.searchinfo.session_key, self._metadata.searchinfo.splunkd_uri
        )
        accounts = accounts_dict.get("accounts", [])

        # run
        if self.account == "_all":
            for account in accounts:
                # account configuration
                account_conf = jira_get_account(
                    self._metadata.searchinfo.session_key,
                    self._metadata.searchinfo.splunkd_uri,
                    account,
                )

                jira_auth_mode = account_conf.get("auth_mode", "basic")
                jira_url = account_conf.get("jira_url", None)
                jira_ssl_certificate_path = account_conf.get(
                    "jira_ssl_certificate_path", None
                )
                jira_ssl_certificate_pem = account_conf.get(
                    "jira_ssl_certificate_pem", None
                )
                jira_username = account_conf.get("username", None)
                jira_password = account_conf.get("jira_password", None)

                # end of get configuration

                # test connectivity systematically, raise an exception only if opt!=0
                connected = False
                connection_failure_message = None
                try:
                    healthcheck_response = jira_test_connectivity(
                        self._metadata.searchinfo.session_key,
                        self._metadata.searchinfo.splunkd_uri,
                        account,
                    )
                    connected = True
                except Exception as e:
                    connection_failure_message = f'JIRA connect verification failed for account="{account}" with exception="{str(e)}"'
                    if int(self.opt) != 0:
                        raise Exception(connection_failure_message)

                # return connection test results
                if int(self.opt) == 0:
                    if connected:
                        yield {
                            "_time": time.time(),
                            "_raw": healthcheck_response,
                            "account": account,
                            "connectivy_test": healthcheck_response.get("status"),
                            "response": healthcheck_response.get("response"),
                            "status_code": healthcheck_response.get("status_code"),
                            "result": healthcheck_response.get("result"),
                        }
                    else:
                        raw = {
                            "account": account,
                            "connectivy_test": "failure",
                            "result": connection_failure_message,
                        }
                        yield {
                            "_time": time.time(),
                            "_raw": raw,
                            "account": account,
                            "connectivy_test": "failure",
                            "result": connection_failure_message,
                        }

                else:
                    if not connected:
                        raise Exception(
                            f'JIRA connect verification failed for account="{account}" with exception="{healthcheck_response.get("response")}"'
                        )

                # Proceed
                if int(self.opt) == 1 and connected:
                    for project in self.get_jira_info(
                        jira_url,
                        jira_auth_mode,
                        jira_username,
                        jira_password,
                        jira_ssl_certificate_path,
                        jira_ssl_certificate_pem,
                        proxy_dict,
                        timeout,
                    ):
                        result_dict = {
                            "_time": time.time(),
                            "account": str(account),
                            "key": project.get("key"),
                            "key_projects": f'{project.get("key")} - {project.get("name")}',
                        }
                        yield {
                            "_time": time.time(),
                            "_raw": result_dict,
                            "account": str(account),
                            "key": project.get("key"),
                            "key_projects": f'{project.get("key")} - {project.get("name")}',
                        }

                if int(self.opt) == 2 and connected:
                    for issue in self.get_jira_info(
                        jira_url,
                        jira_auth_mode,
                        jira_username,
                        jira_password,
                        jira_ssl_certificate_path,
                        jira_ssl_certificate_pem,
                        proxy_dict,
                        timeout,
                    ):
                        result_dict = {
                            "_time": time.time(),
                            "account": str(account),
                            "issues": issue.get("name"),
                        }
                        yield {
                            "_time": time.time(),
                            "_raw": result_dict,
                            "account": str(account),
                            "issues": issue.get("name"),
                        }

                if int(self.opt) == 3 and connected:
                    for priority in self.get_jira_info(
                        jira_url,
                        jira_auth_mode,
                        jira_username,
                        jira_password,
                        jira_ssl_certificate_path,
                        jira_ssl_certificate_pem,
                        proxy_dict,
                        timeout,
                    ):
                        result_dict = {
                            "_time": time.time(),
                            "account": str(account),
                            "priorities": priority.get("name"),
                        }
                        yield {
                            "_time": time.time(),
                            "_raw": result_dict,
                            "account": str(account),
                            "priorities": priority.get("name"),
                        }

                if int(self.opt) == 4 and connected:
                    for status in self.get_jira_info(
                        jira_url,
                        jira_auth_mode,
                        jira_username,
                        jira_password,
                        jira_ssl_certificate_path,
                        jira_ssl_certificate_pem,
                        proxy_dict,
                        timeout,
                    ):
                        result_dict = {
                            "_time": time.time(),
                            "account": str(account),
                            "status": status.get("name"),
                            "statusCategory": status.get("statusCategory").get("name"),
                        }
                        yield {
                            "_time": time.time(),
                            "_raw": result_dict,
                            "account": str(account),
                            "status": status.get("name"),
                            "statusCategory": status.get("statusCategory").get("name"),
                        }

        else:
            # account configuration
            if not self.account in accounts:
                raise ValueError(
                    f"The account={self.account} does not exist, check your inputs and configuration.",
                )

            # get account configuration
            account_conf = jira_get_account(
                self._metadata.searchinfo.session_key,
                self._metadata.searchinfo.splunkd_uri,
                self.account,
            )

            jira_auth_mode = account_conf.get("auth_mode", "basic")
            jira_url = account_conf.get("jira_url", None)
            jira_ssl_certificate_path = account_conf.get(
                "jira_ssl_certificate_path", None
            )
            jira_ssl_certificate_pem = account_conf.get(
                "jira_ssl_certificate_pem", None
            )
            jira_username = account_conf.get("username", None)
            jira_password = account_conf.get("jira_password", None)

            # end of get configuration

            # test connectivity systematically, raise an exception only if opt!=0
            connected = False
            connection_failure_message = None
            try:
                healthcheck_response = jira_test_connectivity(
                    self._metadata.searchinfo.session_key,
                    self._metadata.searchinfo.splunkd_uri,
                    self.account,
                )
                connected = True
            except Exception as e:
                connection_failure_message = f'JIRA connect verification failed for account="{self.account}" with exception="{str(e)}"'
                if int(self.opt) != 0:
                    raise Exception(connection_failure_message)

            # return connection test results
            if int(self.opt) == 0:
                if connected:
                    yield {
                        "_time": time.time(),
                        "_raw": healthcheck_response,
                        "account": self.account,
                        "connectivy_test": healthcheck_response.get("status"),
                        "response": healthcheck_response.get("response"),
                        "status_code": healthcheck_response.get("status_code"),
                        "result": healthcheck_response.get("result"),
                    }
                else:
                    raw = {
                        "account": self.account,
                        "connectivy_test": "failure",
                        "result": connection_failure_message,
                    }
                    yield {
                        "_time": time.time(),
                        "_raw": raw,
                        "account": self.account,
                        "connectivy_test": "failure",
                        "result": connection_failure_message,
                    }

            else:
                if not connected:
                    raise Exception(
                        f'JIRA connect verification failed for account="{self.account}" with exception="{healthcheck_response.get("response")}"'
                    )

            # Proceed
            if int(self.opt) == 1 and connected:
                for project in self.get_jira_info(
                    jira_url,
                    jira_auth_mode,
                    jira_username,
                    jira_password,
                    jira_ssl_certificate_path,
                    jira_ssl_certificate_pem,
                    proxy_dict,
                    timeout,
                ):
                    result_dict = {
                        "_time": time.time(),
                        "account": str(self.account),
                        "key": project.get("key"),
                        "key_projects": f'{project.get("key")} - {project.get("name")}',
                    }
                    yield {
                        "_time": time.time(),
                        "_raw": result_dict,
                        "account": str(self.account),
                        "key": project.get("key"),
                        "key_projects": f'{project.get("key")} - {project.get("name")}',
                    }

            if int(self.opt) == 2 and connected:
                for issue in self.get_jira_info(
                    jira_url,
                    jira_auth_mode,
                    jira_username,
                    jira_password,
                    jira_ssl_certificate_path,
                    jira_ssl_certificate_pem,
                    proxy_dict,
                    timeout,
                ):
                    result_dict = {
                        "_time": time.time(),
                        "account": str(self.account),
                        "issues": issue.get("name"),
                    }
                    yield {
                        "_time": time.time(),
                        "_raw": result_dict,
                        "account": str(self.account),
                        "issues": issue.get("name"),
                    }

            if int(self.opt) == 3 and connected:
                for priority in self.get_jira_info(
                    jira_url,
                    jira_auth_mode,
                    jira_username,
                    jira_password,
                    jira_ssl_certificate_path,
                    jira_ssl_certificate_pem,
                    proxy_dict,
                    timeout,
                ):
                    result_dict = {
                        "_time": time.time(),
                        "account": str(self.account),
                        "priorities": priority.get("name"),
                    }
                    yield {
                        "_time": time.time(),
                        "_raw": result_dict,
                        "account": str(self.account),
                        "priorities": priority.get("name"),
                    }

            if int(self.opt) == 4 and connected:
                for status in self.get_jira_info(
                    jira_url,
                    jira_auth_mode,
                    jira_username,
                    jira_password,
                    jira_ssl_certificate_path,
                    jira_ssl_certificate_pem,
                    proxy_dict,
                    timeout,
                ):
                    result_dict = {
                        "_time": time.time(),
                        "account": str(self.account),
                        "status": status.get("name"),
                        "statusCategory": status.get("statusCategory").get("name"),
                    }
                    yield {
                        "_time": time.time(),
                        "_raw": result_dict,
                        "account": str(self.account),
                        "status": status.get("name"),
                        "statusCategory": status.get("statusCategory").get("name"),
                    }


dispatch(GenerateTextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
