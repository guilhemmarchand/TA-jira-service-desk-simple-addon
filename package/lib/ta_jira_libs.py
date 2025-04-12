#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import requests
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

sys.path.append(
    os.path.join(splunkhome, "etc", "apps", "TA-jira-service-desk-simple-addon", "lib")
)


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
