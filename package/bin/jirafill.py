#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

import sys
import os
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
import base64
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
from ta_jira_libs import jira_get_conf, jira_get_accounts, jira_get_account


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

    # Splunk Cloud vetting notes: SSL verification is always true or the path to the CA bundle for the SSL certificate to be verified
    def test_jira_connect(
        self, account, jira_headers, url, ssl_config, proxy_dict, endpoint
    ):

        try:
            response = requests.get(
                url=self.jira_url(url, endpoint),
                headers=jira_headers,
                verify=ssl_config,
                proxies=proxy_dict,
                timeout=10,
            )
            response.raise_for_status()
            return True, {
                "account": account,
                "status": "success",
                "response": response.text,
                "status_code": response.status_code,
                "result": f"The connection to the JIRA target {url} successfully established and verified.",
            }

        except Exception as e:

            logging.error(
                f'JIRA connect verification failed for account="{account}" with exception="{str(e)}"'
            )
            return False, {
                "account": account,
                "status": "failure",
                "response": str(e),
                "status_code": 500,
                "result": f"The connection to the JIRA target {url} failed.",
            }

    def get_jira_info(self, jira_headers, url, ssl_config, proxy_dict, endpoint):
        response = requests.get(
            url=self.jira_url(url, endpoint),
            headers=jira_headers,
            verify=ssl_config,
            proxies=proxy_dict,
        )
        return response.json()

    def generate(self):

        # get conf
        jira_conf = jira_get_conf(
            self._metadata.searchinfo.session_key, self._metadata.searchinfo.splunkd_uri
        )

        # set loglevel
        log.setLevel(jira_conf["logging"]["loglevel"])

        # global configuration
        proxy_conf = jira_conf["proxy"]
        proxy_dict = proxy_conf.get("proxy_dict", {})

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
                    "ssl_certificate_path", None
                )
                jira_username = account_conf.get("username", None)
                jira_password = account_conf.get("jira_password", None)

                # end of get configuration

                # Build the authentication header for JIRA
                if str(jira_auth_mode) == "basic":
                    authorization = f"{jira_username}:{jira_password}"
                    b64_auth = base64.b64encode(authorization.encode()).decode()
                    jira_headers = {
                        "Authorization": f"Basic {b64_auth}",
                        "Content-Type": "application/json",
                    }
                elif str(jira_auth_mode) == "pat":
                    jira_headers = {
                        "Authorization": f"Bearer {str(jira_password)}",
                        "Content-Type": "application/json",
                    }

                # SSL verification is always true or the path to the CA bundle for the SSL certificate to be verified
                if jira_ssl_certificate_path and os.path.isfile(
                    jira_ssl_certificate_path
                ):
                    ssl_config = str(jira_ssl_certificate_path)
                else:
                    ssl_config = True

                #
                # Process
                #

                # test connectivity systematically
                connected, healthcheck_response = self.test_jira_connect(
                    account,
                    jira_headers,
                    jira_url,
                    ssl_config,
                    proxy_dict,
                    "myself",
                )

                # return connection test results
                if int(self.opt) == 0:

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
                    if not connected:
                        raise Exception(
                            f'JIRA connect verification failed for account="{account}" with exception="{healthcheck_response.get("response")}"'
                        )

                #
                # Get data
                #

                # Proceed
                if int(self.opt) == 1 and connected:
                    for project in self.get_jira_info(
                        jira_headers,
                        jira_url,
                        ssl_config,
                        proxy_dict,
                        "project",
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
                        jira_headers,
                        jira_url,
                        ssl_config,
                        proxy_dict,
                        "issuetype",
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
                        jira_headers,
                        jira_url,
                        ssl_config,
                        proxy_dict,
                        "priority",
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
                        jira_headers, jira_url, ssl_config, proxy_dict, "status"
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

            # Stop here if we cannot find the submitted account
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
            jira_ssl_certificate_path = account_conf.get("ssl_certificate_path", None)
            jira_username = account_conf.get("username", None)
            jira_password = account_conf.get("jira_password", None)
            # end of get configuration

            # Build the authentication header for JIRA
            if str(jira_auth_mode) == "basic":
                authorization = f"{jira_username}:{jira_password}"
                b64_auth = base64.b64encode(authorization.encode()).decode()
                jira_headers = {
                    "Authorization": f"Basic {b64_auth}",
                    "Content-Type": "application/json",
                }
            elif str(jira_auth_mode) == "pat":
                jira_headers = {
                    "Authorization": f"Bearer {str(jira_password)}",
                    "Content-Type": "application/json",
                }

            # Splunk Cloud vetting notes: SSL verification is always true or the path to the CA bundle for the SSL certificate to be verified
            if jira_ssl_certificate_path and os.path.isfile(jira_ssl_certificate_path):
                ssl_config = str(jira_ssl_certificate_path)
            else:
                ssl_config = True

            # test connectivity systematically
            connected, healthcheck_response = self.test_jira_connect(
                self.account,
                jira_headers,
                jira_url,
                ssl_config,
                proxy_dict,
                "myself",
            )

            # return connection test results
            if int(self.opt) == 0:

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
                if not connected:
                    raise Exception(
                        f'JIRA connect verification failed for account="{self.account}" with exception="{healthcheck_response.get("response")}"'
                    )

                if int(self.opt) == 1 and connected:
                    for project in self.get_jira_info(
                        jira_headers, jira_url, ssl_config, proxy_dict, "project"
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
                        jira_headers, jira_url, ssl_config, proxy_dict, "issuetype"
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
                        jira_headers, jira_url, ssl_config, proxy_dict, "priority"
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
                        jira_headers, jira_url, ssl_config, proxy_dict, "status"
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
