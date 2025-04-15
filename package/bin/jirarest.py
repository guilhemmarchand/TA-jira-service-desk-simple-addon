#!/usr/bin/env python
# coding=utf-8

import json
import sys
import os
import time
import requests
import logging
from logging.handlers import RotatingFileHandler
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = RotatingFileHandler(
    f"{splunkhome}/var/log/splunk/ta_jira_jirarest.log",
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


@Configuration(distributed=False)
class GenerateTextCommand(GeneratingCommand):

    account = Option(
        doc="""
        **Syntax:** **account=****
        **Description:** JIRA account to be used, if unspecified the first account configured will be taken into account.""",
        require=False,
        default=None,
    )
    method = Option(
        doc="""
        **Syntax:** **method=****
        **Description:** method to use for API target. DELETE GET POST PUT are supported.""",
        require=False,
        validate=validators.Match("method", r"^(DELETE|GET|POST|PUT)$"),
    )
    json_request = Option(
        doc="""
        **Syntax:** **json_request=***JSON request*
        **Description:** JSON-formatted json_request.""",
        require=False,
        validate=validators.Match("json_request", r"^{.+}$"),
    )
    target = Option(require=True)

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

        # set timeout
        timeout = int(jira_conf["advanced_configuration"].get("timeout", 120))

        # get all acounts
        accounts_dict = jira_get_accounts(
            self._metadata.searchinfo.session_key, self._metadata.searchinfo.splunkd_uri
        )
        accounts = accounts_dict.get("accounts", [])

        # define the account target
        if not self.account or self.account == "_any":
            account = str(accounts[0])
        else:
            account = str(self.account)

        # account configuration
        account_conf = jira_get_account(
            self._metadata.searchinfo.session_key,
            self._metadata.searchinfo.splunkd_uri,
            account,
        )

        jira_auth_mode = account_conf.get("auth_mode", "basic")
        jira_url = account_conf.get("jira_url", None)
        jira_ssl_certificate_path = account_conf.get("jira_ssl_certificate_path", None)
        jira_ssl_certificate_pem = account_conf.get("jira_ssl_certificate_pem", None)
        jira_username = account_conf.get("username", None)
        jira_password = account_conf.get("jira_password", None)

        # Build the authentication header for JIRA
        jira_headers = jira_build_headers(jira_auth_mode, jira_username, jira_password)

        # SSL verification is always true or the path to the CA bundle for the SSL certificate to be verified
        # Handle SSL certificate configuration
        ssl_config, temp_cert_file = jira_handle_ssl_certificate(
            jira_ssl_certificate_path, jira_ssl_certificate_pem
        )

        # verify the method
        if self.method:
            jira_method = self.method
        else:
            jira_method = "GET"

        if self.json_request:
            body_dict = json.loads(self.json_request)
        else:
            if jira_method == "POST" or jira_method == "PUT":
                raise Exception(
                    f"jirarest: method {jira_method} requires a valid json_request. It is empty"
                )

        # test connectivity systematically
        connected = False
        try:
            healthcheck_response = jira_test_connectivity(
                self._metadata.searchinfo.session_key,
                self._metadata.searchinfo.splunkd_uri,
                account,
            )
            connected = True
            logging.debug(
                f'JIRA connect verification successful for account="{account}", response="{json.dumps(healthcheck_response)}"'
            )
        except Exception as e:
            raise Exception(
                f'JIRA connect verification failed for account="{account}" with exception="{str(e)}"'
            )

        #
        # main
        #

        if connected:

            # set proper headers
            if jira_method == "GET":
                jira_fields_response = requests.get(
                    url=f"{str(jira_url)}/{str(self.target)}",
                    headers=jira_headers,
                    verify=ssl_config,
                    proxies=proxy_dict,
                    timeout=timeout,
                )
            elif jira_method == "DELETE":
                jira_fields_response = requests.delete(
                    url=f"{str(jira_url)}/{str(self.target)}",
                    headers=jira_headers,
                    verify=ssl_config,
                    proxies=proxy_dict,
                    timeout=timeout,
                )
            elif jira_method == "POST":
                jira_fields_response = requests.post(
                    url=f"{str(jira_url)}/{str(self.target)}",
                    data=json.dumps(body_dict).encode("utf-8"),
                    headers=jira_headers,
                    verify=ssl_config,
                    proxies=proxy_dict,
                    timeout=timeout,
                )
            elif jira_method == "PUT":
                jira_fields_response = requests.put(
                    url=f"{str(jira_url)}/{str(self.target)}",
                    data=json.dumps(body_dict).encode("utf-8"),
                    headers=jira_headers,
                    verify=ssl_config,
                    proxies=proxy_dict,
                    timeout=timeout,
                )

            # Attenpt to get a JSON response, and render in Splunk
            try:

                json_response = jira_fields_response.json()
                data = {"_time": time.time(), "_raw": json.dumps(json_response)}
                yield data

            except Exception as e:

                # Build a custom response for Splunk dynamically

                # Create an action field, convenient to quickly understanding when things go wrong
                if jira_fields_response.status_code in (200, 201, 204):
                    response_action = "success"
                else:
                    response_action = "failure"

                # render
                if jira_fields_response.text:
                    json_response = f'{{"action": "{response_action}", "status_code": "{jira_fields_response.status_code}", "text": "{jira_fields_response.text}"}}'
                else:
                    json_response = f'{{"action": "{response_action}", "status_code": "{jira_fields_response.status_code}"}}'
                data = {
                    "_time": time.time(),
                    "_raw": str(
                        json.dumps(json.loads(json_response, strict=False), indent=4)
                    ),
                }

                yield data


dispatch(GenerateTextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
