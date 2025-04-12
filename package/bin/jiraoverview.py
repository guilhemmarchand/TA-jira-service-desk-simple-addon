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
    f"{splunkhome}/var/log/splunk/ta_jira_jiraoverview.log",
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

# Import JIRA libs
from ta_jira_libs import (
    test_jira_connect,
    jira_get_conf,
    jira_get_accounts,
    jira_get_account,
)


@Configuration(distributed=False)
class GenerateTextCommand(GeneratingCommand):

    # Proceed
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

        # loop through the accounts
        for account in accounts:

            # account configuration
            account_conf = jira_get_account(
                self._metadata.searchinfo.session_key,
                self._metadata.searchinfo.splunkd_uri,
                account,
            )

            jira_auth_mode = account_conf.get("auth_mode", "basic")
            jira_url = account_conf.get("jira_url", None)
            jira_ssl_certificate_path = account_conf.get("ssl_certificate_path", None)
            jira_username = account_conf.get("username", None)
            jira_password = account_conf.get("jira_password", None)

            # verify the url
            if not jira_url.startswith("https://"):
                jira_url = f"https://{str(jira_url)}"

            # handle SSL verification and bundle
            if jira_ssl_certificate_path and os.path.isfile(jira_ssl_certificate_path):
                ssl_config = str(jira_ssl_certificate_path)
            else:
                ssl_config = True

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

            # ensures connectivity and proceed
            try:
                connectivity_check = test_jira_connect(
                    account, jira_headers, jira_url, ssl_config, proxy_dict
                )
                logging.debug(
                    f'account="{account}", connectivity_check="{connectivity_check}"'
                )

            except Exception as e:
                logging.error(str(e))
                raise Exception(str(e))

            # Get the list of projects
            projects_list = []
            jira_check_url = f"{jira_url}/rest/api/latest/project"
            try:
                response = requests.get(
                    url=jira_check_url,
                    headers=jira_headers,
                    verify=ssl_config,
                    proxies=proxy_dict,
                    timeout=10,
                )
                if response.status_code not in (200, 201, 204):
                    raise Exception(
                        f'JIRA operation failed, account="{account}", url="{jira_check_url}", HTTP Error="{response.status_code}", HTTP Response="{response.text}"'
                    )
                else:
                    logging.debug(response.text)

                    for project_response in json.loads(response.text):
                        projects_list.append(project_response.get("key"))

                logging.debug(f'list of projects="{projects_list}"')

            except Exception as e:
                logging.error(
                    f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                )
                raise Exception(
                    f'JIRA operation failedfor account="{account}" with exception="{str(e)}"'
                )

            # Loop through the projects, and return the KPIs
            for project in projects_list:

                # total count of issues
                jira_check_url = f"{jira_url}/rest/api/latest/search?jql=project={project}&maxResults=0"
                try:
                    response = requests.get(
                        url=jira_check_url,
                        headers=jira_headers,
                        verify=ssl_config,
                        proxies=proxy_dict,
                        timeout=10,
                    )
                    if response.status_code not in (200, 201, 204):
                        logging.error(
                            f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                        )
                    else:
                        logging.debug(response.text)

                        yield_dict = {
                            "account": account,
                            "project": project,
                            "type": "total_issues",
                            "value": json.loads(response.text).get("total"),
                        }

                        yield {
                            "_time": time.time(),
                            "_raw": yield_dict,
                            "account": account,
                            "project": project,
                            "type": "total_issues",
                            "value": json.loads(response.text).get("total"),
                        }

                except Exception as e:
                    logging.error(
                        f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                    )

                # total done
                jira_check_url = f"{jira_url}/rest/api/latest/search?jql=project={project}%20AND%20statuscategory%20IN%20%28%22Done%22%29&maxResults=0"
                try:
                    response = requests.get(
                        url=jira_check_url,
                        headers=jira_headers,
                        verify=ssl_config,
                        proxies=proxy_dict,
                        timeout=10,
                    )
                    if response.status_code not in (200, 201, 204):
                        logging.error(
                            f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                        )
                    else:
                        logging.debug(response.text)

                        yield_dict = {
                            "account": account,
                            "project": project,
                            "type": "total_done",
                            "value": json.loads(response.text).get("total"),
                        }

                        yield {
                            "_time": time.time(),
                            "_raw": yield_dict,
                            "account": account,
                            "project": project,
                            "type": "total_done",
                            "value": json.loads(response.text).get("total"),
                        }

                except Exception as e:
                    logging.error(
                        f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                    )

                # total todo
                jira_check_url = f"{jira_url}/rest/api/latest/search?jql=project={project}%20AND%20statuscategory%20IN%20%28%22To%20Do%22%29&maxResults=0"
                try:
                    response = requests.get(
                        url=jira_check_url,
                        headers=jira_headers,
                        verify=ssl_config,
                        proxies=proxy_dict,
                        timeout=10,
                    )
                    if response.status_code not in (200, 201, 204):
                        logging.error(
                            f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                        )
                    else:
                        logging.debug(response.text)

                        yield_dict = {
                            "account": account,
                            "project": project,
                            "type": "total_to_do",
                            "value": json.loads(response.text).get("total"),
                        }

                        yield {
                            "_time": time.time(),
                            "_raw": yield_dict,
                            "account": account,
                            "project": project,
                            "type": "total_to_do",
                            "value": json.loads(response.text).get("total"),
                        }

                except Exception as e:
                    logging.error(
                        f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                    )

                # total todo
                jira_check_url = f"{jira_url}/rest/api/latest/search?jql=project={project}%20AND%20statuscategory%20IN%20%28%22In%20Progress%22%29&maxResults=0"
                try:
                    response = requests.get(
                        url=jira_check_url,
                        headers=jira_headers,
                        verify=ssl_config,
                        proxies=proxy_dict,
                        timeout=10,
                    )
                    if response.status_code not in (200, 201, 204):
                        logging.error(
                            f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                        )
                    else:
                        logging.debug(response.text)

                        yield_dict = {
                            "account": account,
                            "project": project,
                            "type": "total_in_progress",
                            "value": json.loads(response.text).get("total"),
                        }

                        yield {
                            "_time": time.time(),
                            "_raw": yield_dict,
                            "account": account,
                            "project": project,
                            "type": "total_in_progress",
                            "value": json.loads(response.text).get("total"),
                        }

                except Exception as e:
                    logging.error(
                        f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                    )


dispatch(GenerateTextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
