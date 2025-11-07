#!/usr/bin/env python
# coding=utf-8

import sys
import os
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
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
    jira_get_conf,
    jira_get_accounts,
    jira_get_account,
    jira_build_headers,
    jira_handle_ssl_certificate,
    jira_test_connectivity,
)


def count_issues_with_pagination(jira_url, jira_headers, ssl_config, proxy_dict, timeout, jql_query, account):
    """
    Count issues using the API v3 search endpoint with pagination.
    Returns the total count of issues matching the JQL query.
    """
    jira_check_url = f"{jira_url}/rest/api/3/search/jql"
    total_count = 0
    start_at = 0
    max_results = 1000  # Maximum allowed by API
    max_pages = 200  # Safety limit to prevent infinite loops (200k issues max)
    page_count = 0
    
    while page_count < max_pages:
        params = {
            "jql": jql_query,
            "maxResults": max_results,
            "startAt": start_at,
            "fields": "id"  # Only get ID field to minimize response size
        }
            
        try:
            response = requests.get(
                url=jira_check_url,
                headers=jira_headers,
                params=params,
                verify=ssl_config,
                proxies=proxy_dict,
                timeout=timeout,
            )
            
            if response.status_code not in (200, 201, 204):
                logging.error(
                    f'JIRA operation failed for account="{account}", url="{jira_check_url}", HTTP Error="{response.status_code}", HTTP Response="{response.text}"'
                )
                return None
                
            response_data = json.loads(response.text)
            issues = response_data.get("issues", [])
            total_count += len(issues)
            page_count += 1
            
            # Debug: Log the full response structure to understand pagination
            logging.debug(f"API Response keys: {list(response_data.keys())}")
            logging.debug(f"Page {page_count}: startAt={start_at}, issues_count={len(issues)}, total_so_far={total_count}")
            logging.debug(f"Response fields - isLast: {response_data.get('isLast')}, total: {response_data.get('total')}, startAt: {response_data.get('startAt')}, maxResults: {response_data.get('maxResults')}")
            
            # Log progress every 10 pages
            if page_count % 10 == 0:
                logging.info(f"Progress: {page_count} pages processed, {total_count} issues counted so far")
            
            # Check if this is the last page
            if response_data.get("isLast", False):
                logging.debug(f"Reached last page (isLast=True)")
                break
                
            # Check if we got fewer issues than requested (end of results)
            if len(issues) < max_results:
                logging.debug(f"Reached end of results (got {len(issues)} < {max_results})")
                break
                
            # Check if we've reached the total count (if available)
            api_total = response_data.get("total")
            if api_total is not None and total_count >= api_total:
                logging.debug(f"Reached API total count: {api_total}")
                break
                
            # Move to next page
            start_at += max_results
                
        except Exception as e:
            logging.error(
                f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
            )
            return None
    
    if page_count >= max_pages:
        logging.warning(f"Reached safety limit of {max_pages} pages. Total counted: {total_count}")
            
    return total_count


@Configuration(distributed=False)
class GenerateTextCommand(GeneratingCommand):
    """
    A Splunk search command that provides an overview of JIRA projects and their metrics.
    This command retrieves key performance indicators (KPIs) for all configured JIRA projects.

    The command:
    - Connects to all configured JIRA accounts
    - Retrieves the list of projects for each account
    - Collects metrics for each project including:
        - Total number of issues
        - Number of completed issues
    """

    def generate(self):
        """
        Generates the search results by collecting JIRA project metrics.

        This method:
        1. Retrieves the JIRA configuration
        2. Sets up logging and proxy settings
        3. Gets the list of configured accounts
        4. For each account:
           - Retrieves account configuration
           - Tests connectivity
           - Gets the list of projects
           - For each project:
             - Gets total issue count
             - Gets completed issue count
             - Yields the metrics

        The method handles:
        - SSL certificate verification
        - Proxy configuration
        - Error handling and logging
        - Multiple JIRA accounts

        Yields:
            dict: A dictionary containing:
                - _time: The timestamp of the request
                - _raw: The metrics data
                - account: The JIRA account name
                - project: The project key
                - type: The metric type ('total_issues' or 'total_done')
                - value: The metric value
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

        # loop through the accounts
        for account in accounts:

            # account configuration
            account_conf = jira_get_account(
                self._metadata.searchinfo.session_key,
                self._metadata.searchinfo.splunkd_uri,
                account,
            )

            jira_auth_mode = account_conf.get("jira_auth_mode", "basic")
            jira_url = account_conf.get("jira_url", None)
            jira_ssl_certificate_path = account_conf.get(
                "jira_ssl_certificate_path", None
            )
            jira_ssl_certificate_pem = account_conf.get(
                "jira_ssl_certificate_pem", None
            )
            jira_username = account_conf.get("username", None)
            jira_password = account_conf.get("jira_password", None)

            # verify the url
            if not jira_url.startswith("https://"):
                jira_url = f"https://{str(jira_url)}"

            # Build the authentication header for JIRA
            jira_headers = jira_build_headers(
                jira_auth_mode, jira_username, jira_password
            )

            # SSL verification is always true, or the path to the SSL bundle, or the SSL bundle itself
            ssl_config, temp_cert_file = jira_handle_ssl_certificate(
                jira_ssl_certificate_path, jira_ssl_certificate_pem
            )

            # ensures connectivity and proceed
            # test connectivity systematically
            connected = False
            try:
                healthcheck_response = jira_test_connectivity(
                    self._metadata.searchinfo.session_key,
                    self._metadata.searchinfo.splunkd_uri,
                    account,
                )
                connected = True
            except Exception as e:
                raise Exception(
                    f'JIRA connect verification failed for account="{account}" with exception="{str(e)}"'
                )

            if not connected:
                raise Exception(
                    f'JIRA connect verification failed for account="{account}" with exception="{healthcheck_response.get("response")}"'
                )

            # Get the list of projects
            projects_list = []
            jira_check_url = f"{jira_url}/rest/api/latest/project/search"
            start_at = 0
            max_results = 50
            
            try:
                while True:
                    response = requests.get(
                        url=jira_check_url,
                        headers=jira_headers,
                        verify=ssl_config,
                        proxies=proxy_dict,
                        timeout=timeout,
                        params={"startAt": start_at, "maxResults": max_results}
                    )
                    if response.status_code not in (200, 201, 204):
                        raise Exception(
                            f'JIRA operation failed, account="{account}", url="{jira_check_url}", HTTP Error="{response.status_code}", HTTP Response="{response.text}"'
                        )
                    else:
                        logging.debug(response.text)
                        response_data = json.loads(response.text)
                        
                        # Extract projects from the new response format
                        for project_response in response_data.get("values", []):
                            projects_list.append(project_response.get("key"))
                        
                        # Check if we've retrieved all projects
                        if response_data.get("isLast", True):
                            break
                            
                        start_at = response_data.get("startAt", 0) + max_results

                logging.debug(f'list of projects="{projects_list}"')

            except Exception as e:
                logging.error(
                    f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                )
                raise Exception(
                    f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                )

            # Loop through the projects, and return the KPIs
            for project in projects_list:

                # total count of issues
                try:
                    total_count = count_issues_with_pagination(
                        jira_url, jira_headers, ssl_config, proxy_dict, timeout,
                        f"project={project}", account
                    )
                    
                    if total_count is not None:
                        logging.debug(f"Total issues count for project {project}: {total_count}")
                        
                        yield_dict = {
                            "account": account,
                            "project": project,
                            "type": "total_issues",
                            "value": total_count,
                        }

                        yield {
                            "_time": time.time(),
                            "_raw": yield_dict,
                            "account": account,
                            "project": project,
                            "type": "total_issues",
                            "value": total_count,
                        }
                    else:
                        logging.error(f"Failed to get total issues count for project {project}")

                except Exception as e:
                    logging.error(
                        f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                    )

                # total done
                try:
                    total_count = count_issues_with_pagination(
                        jira_url, jira_headers, ssl_config, proxy_dict, timeout,
                        f"project={project} AND statuscategory IN (\"Done\")", account
                    )
                    
                    if total_count is not None:
                        logging.debug(f"Total done count for project {project}: {total_count}")
                        
                        yield_dict = {
                            "account": account,
                            "project": project,
                            "type": "total_done",
                            "value": total_count,
                        }

                        yield {
                            "_time": time.time(),
                            "_raw": yield_dict,
                            "account": account,
                            "project": project,
                            "type": "total_done",
                            "value": total_count,
                        }
                    else:
                        logging.error(f"Failed to get total done count for project {project}")

                except Exception as e:
                    logging.error(
                        f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                    )

                # total todo
                try:
                    total_count = count_issues_with_pagination(
                        jira_url, jira_headers, ssl_config, proxy_dict, timeout,
                        f"project={project} AND statuscategory IN (\"To Do\")", account
                    )
                    
                    if total_count is not None:
                        logging.debug(f"Total to-do count for project {project}: {total_count}")
                        
                        yield_dict = {
                            "account": account,
                            "project": project,
                            "type": "total_to_do",
                            "value": total_count,
                        }

                        yield {
                            "_time": time.time(),
                            "_raw": yield_dict,
                            "account": account,
                            "project": project,
                            "type": "total_to_do",
                            "value": total_count,
                        }
                    else:
                        logging.error(f"Failed to get total to-do count for project {project}")

                except Exception as e:
                    logging.error(
                        f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                    )

                # total in progress
                try:
                    total_count = count_issues_with_pagination(
                        jira_url, jira_headers, ssl_config, proxy_dict, timeout,
                        f"project={project} AND statuscategory IN (\"In Progress\")", account
                    )
                    
                    if total_count is not None:
                        logging.debug(f"Total in-progress count for project {project}: {total_count}")
                        
                        yield_dict = {
                            "account": account,
                            "project": project,
                            "type": "total_in_progress",
                            "value": total_count,
                        }

                        yield {
                            "_time": time.time(),
                            "_raw": yield_dict,
                            "account": account,
                            "project": project,
                            "type": "total_in_progress",
                            "value": total_count,
                        }
                    else:
                        logging.error(f"Failed to get total in-progress count for project {project}")

                except Exception as e:
                    logging.error(
                        f'JIRA operation failed for account="{account}" with exception="{str(e)}"'
                    )


dispatch(GenerateTextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
