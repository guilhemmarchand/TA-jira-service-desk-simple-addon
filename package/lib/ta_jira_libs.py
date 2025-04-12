#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import requests
import json
import logging
import urllib3
from requests.structures import CaseInsensitiveDict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

sys.path.append(
    os.path.join(splunkhome, "etc", "apps", "TA-jira-service-desk-simple-addon", "lib")
)


# get configuration
def jira_get_conf(session_key, splunkd_uri):
    """
    get system wide conf with least privilege approach
    """

    # Ensure splunkd_uri starts with "https://"
    if not splunkd_uri.startswith("https://"):
        splunkd_uri = f"https://{splunkd_uri}"

    # Build header and target URL
    headers = CaseInsensitiveDict()
    headers["Authorization"] = f"Splunk {session_key}"
    target_url = f"{splunkd_uri}/services/jira_service_desk/manager/get_conf"

    # Create a requests session for better performance
    session = requests.Session()
    session.headers.update(headers)

    try:
        # Use a context manager to handle the request
        with session.get(target_url, verify=False) as response:
            if response.ok:
                logging.debug(f'Success retrieving conf, data="{response.text}"')
                response_json = response.json()
                return response_json
            else:
                error_message = f'Failed to retrieve conf, status_code={response.status_code}, response_text="{response.text}"'
                logging.error(error_message)
                raise Exception(error_message)

    except Exception as e:
        error_message = f'Failed to retrieve conf, exception="{str(e)}"'
        logging.error(error_message)
        raise Exception(error_message)


# get accounts
def jira_get_accounts(session_key, splunkd_uri):
    """
    get list of configured accounts with least privilege approach
    """

    # Ensure splunkd_uri starts with "https://"
    if not splunkd_uri.startswith("https://"):
        splunkd_uri = f"https://{splunkd_uri}"

    # Build header and target URL
    headers = CaseInsensitiveDict()
    headers["Authorization"] = f"Splunk {session_key}"
    target_url = f"{splunkd_uri}/services/jira_service_desk/manager/list_accounts"

    # Create a requests session for better performance
    session = requests.Session()
    session.headers.update(headers)

    try:
        # Use a context manager to handle the request
        with session.get(target_url, verify=False) as response:
            if response.ok:
                logging.debug(f'Success retrieving accounts, data="{response.text}"')
                response_json = response.json()
                return response_json
            else:
                error_message = f'Failed to retrieve accounts, status_code={response.status_code}, response_text="{response.text}"'
                logging.error(error_message)
                raise Exception(error_message)

    except Exception as e:
        error_message = f'Failed to retrieve accounts, exception="{str(e)}"'
        logging.error(error_message)
        raise Exception(error_message)


# get account
def jira_get_account(session_key, splunkd_uri, account):
    """
    get account creds with least privilege approach
    """

    # Ensure splunkd_uri starts with "https://"
    if not splunkd_uri.startswith("https://"):
        splunkd_uri = f"https://{splunkd_uri}"

    # Build header and target URL
    headers = CaseInsensitiveDict()
    headers["Authorization"] = f"Splunk {session_key}"
    target_url = f"{splunkd_uri}/services/jira_service_desk/manager/get_account"

    # Create a requests session for better performance
    session = requests.Session()
    session.headers.update(headers)

    try:
        # Use a context manager to handle the request
        with session.post(
            target_url, data=json.dumps({"account": account}), verify=False
        ) as response:
            if response.ok:
                logging.debug(f'Success retrieving account, data="{response.text}"')
                response_json = response.json()
                return response_json
            else:
                error_message = f'Failed to retrieve account, status_code={response.status_code}, response_text="{response.text}"'
                logging.error(error_message)
                raise Exception(error_message)

    except Exception as e:
        error_message = f'Failed to retrieve account, exception="{str(e)}"'
        logging.error(error_message)
        raise Exception(error_message)


# connectivity check
# Splunk Cloud vetting notes: SSL verification is always true or the path to the CA bundle for the SSL certificate to be verified
def test_jira_connect(account, jira_headers, jira_url, ssl_config, proxy_dict):

    jira_check_url = f"{jira_url}/rest/api/latest/myself"
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
                f'JIRA connect verification failed, account="{account}", url="{jira_check_url}", HTTP Error="{response.status_code}", HTTP Response="{response.text}"'
            )
        else:
            return {
                "status": "success",
                "response": response.text,
                "status_code": response.status_code,
            }

    except Exception as e:
        logging.error(
            f'JIRA connect verification failed for account="{account}" with exception="{str(e)}"'
        )
        raise Exception(
            f'JIRA connect verification failed for account="{account}" with exception="{str(e)}"'
        )
