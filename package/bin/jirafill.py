#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

import sys
import os
import splunk
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
import base64
import logging

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = logging.FileHandler(
    splunkhome + "/var/log/splunk/ta_jira_jirafill.log", "a"
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


@Configuration(distributed=False)
class GenerateTextCommand(GeneratingCommand):

    account = Option(require=True)
    opt = Option(require=True, validate=validators.Integer(0))

    def jira_url(self, url, endpoint):
        # For Splunk Cloud vetting, the URL must start with https://
        if not url.startswith("https://"):
            return "https://%s/rest/api/latest/%s" % (url, endpoint)

        else:
            return "%s/rest/api/latest/%s" % (url, endpoint)

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
            if response.status_code not in (200, 201, 204):
                raise Exception(
                    'JIRA connect verification failed, account="{}", url="{}", HTTP Error="{}", HTTP Response="{}"'.format(
                        account,
                        self.jira_url(url, endpoint),
                        response.status_code,
                        response.text,
                    )
                )
            else:
                return {
                    "status": "success",
                    "response": response.text,
                    "status_code": response.status_code,
                }

        except Exception as e:
            logging.error(
                'JIRA connect verification failed for account="{}" with exception="{}"'.format(
                    account, str(e)
                )
            )
            raise Exception(
                'JIRA connect verification failed for account="{}" with exception="{}"'.format(
                    account, str(e)
                )
            )

    def get_jira_info(self, jira_headers, url, ssl_config, proxy_dict, endpoint):
        response = requests.get(
            url=self.jira_url(url, endpoint),
            headers=jira_headers,
            verify=ssl_config,
            proxies=proxy_dict,
        )
        return response.json()

    def generate(self):

        # set loglevel
        loglevel = "INFO"
        conf_file = "ta_service_desk_simple_addon_settings"
        confs = self.service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == "logging":
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        logginglevel = logging.getLevelName(loglevel)
        log.setLevel(logginglevel)

        # credential store
        storage_passwords = self.service.storage_passwords

        # global configuration
        proxy_enabled = "0"
        proxy_url = None
        proxy_dict = None
        proxy_username = None
        for stanza in confs:
            if stanza.name == "proxy":
                for key, value in stanza.content.items():
                    if key == "proxy_enabled":
                        proxy_enabled = value
                    if key == "proxy_port":
                        proxy_port = value
                    if key == "proxy_type":
                        proxy_type = value
                    if key == "proxy_url":
                        proxy_url = value
                    if key == "proxy_username":
                        proxy_username = value

        if proxy_enabled == "1":

            # get proxy password
            if proxy_username:
                proxy_password = None

                # get proxy password, if any
                credential_realm = "__REST_CREDENTIAL__#TA-jira-service-desk-simple-addon#configs/conf-ta_service_desk_simple_addon_settings"
                for credential in storage_passwords:
                    if (
                        credential.content.get("realm") == str(credential_realm)
                        and credential.content.get("clear_password").find(
                            "proxy_password"
                        )
                        > 0
                    ):
                        proxy_password = json.loads(
                            credential.content.get("clear_password")
                        ).get("proxy_password")
                        break

                if proxy_type == "http":
                    proxy_dict = {
                        "http": "http://"
                        + proxy_username
                        + ":"
                        + proxy_password
                        + "@"
                        + proxy_url
                        + ":"
                        + proxy_port,
                        "https": "https://"
                        + proxy_username
                        + ":"
                        + proxy_password
                        + "@"
                        + proxy_url
                        + ":"
                        + proxy_port,
                    }
                else:
                    proxy_dict = {
                        "http": str(proxy_type)
                        + "://"
                        + proxy_username
                        + ":"
                        + proxy_password
                        + "@"
                        + proxy_url
                        + ":"
                        + proxy_port,
                        "https": str(proxy_type)
                        + "://"
                        + proxy_username
                        + ":"
                        + proxy_password
                        + "@"
                        + proxy_url
                        + ":"
                        + proxy_port,
                    }

            else:
                proxy_dict = {
                    "http": proxy_url + ":" + proxy_port,
                    "https": proxy_url + ":" + proxy_port,
                }

        # get all acounts
        accounts = []
        conf_file = "ta_service_desk_simple_addon_account"
        confs = self.service.confs[str(conf_file)]
        for stanza in confs:
            # get all accounts
            for name in stanza.name:
                accounts.append(stanza.name)
                break

        # run
        if self.account == "_all":

            for account in accounts:

                # account configuration
                jira_ssl_certificate_validation = None
                jira_ssl_certificate_path = None
                username = None
                password = None

                conf_file = "ta_service_desk_simple_addon_account"
                confs = self.service.confs[str(conf_file)]
                for stanza in confs:

                    if stanza.name == str(account):
                        for key, value in stanza.content.items():
                            if key == "jira_url":
                                jira_url = value
                            if key == "jira_ssl_certificate_validation":
                                jira_ssl_certificate_validation = value
                            if key == "jira_ssl_certificate_path":
                                jira_ssl_certificate_path = value
                            if key == "auth_type":
                                auth_type = value
                            if key == "jira_auth_mode":
                                jira_auth_mode = value
                            if key == "username":
                                username = value

                # end of get configuration

                credential_username = str(account) + "``splunk_cred_sep``1"
                credential_realm = "__REST_CREDENTIAL__#TA-jira-service-desk-simple-addon#configs/conf-ta_service_desk_simple_addon_account"
                for credential in storage_passwords:
                    if (
                        credential.content.get("username") == str(credential_username)
                        and credential.content.get("realm") == str(credential_realm)
                        and credential.content.get("clear_password").find("password")
                        > 0
                    ):
                        password = json.loads(
                            credential.content.get("clear_password")
                        ).get("password")
                        break

                # Build the authentication header for JIRA
                if str(jira_auth_mode) == "basic":
                    authorization = username + ":" + password
                    b64_auth = base64.b64encode(authorization.encode()).decode()
                    jira_headers = {
                        "Authorization": "Basic %s" % b64_auth,
                        "Content-Type": "application/json",
                    }
                elif str(jira_auth_mode) == "pat":
                    jira_headers = {
                        "Authorization": "Bearer %s" % str(password),
                        "Content-Type": "application/json",
                    }

                # SSL verification is always true or the path to the CA bundle for the SSL certificate to be verified
                if jira_ssl_certificate_path and os.path.isfile(
                    jira_ssl_certificate_path
                ):
                    ssl_config = str(jira_ssl_certificate_path)
                else:
                    ssl_config = True

                # test connectivity per account
                if self.opt == 0:

                    try:
                        response = self.test_jira_connect(
                            account,
                            jira_headers,
                            jira_url,
                            ssl_config,
                            proxy_dict,
                            "myself",
                        )
                        response_dict = {
                            "account": account,
                            "connectivy_test": response.get("status"),
                            "response": response.get("response"),
                            "status_code": response.get("status_code"),
                        }

                        yield {
                            "_time": time.time(),
                            "_raw": response_dict,
                            "account": account,
                            "connectivy_test": response.get("status"),
                            "response": response.get("response"),
                            "status_code": response.get("status_code"),
                        }

                    except Exception as e:

                        response_dict = {
                            "account": account,
                            "connectivy_test": "failure",
                            "exception": str(e),
                        }

                        yield {
                            "_time": time.time(),
                            "_raw": response_dict,
                            "account": account,
                            "connectivy_test": "failure",
                            "exception": str(e),
                        }

                #
                # Get data
                #

                if self.opt:

                    # Check the connectivity, fails and raise an exception accordingly
                    try:
                        connectivity_check = self.test_jira_connect(
                            account,
                            jira_headers,
                            jira_url,
                            ssl_config,
                            proxy_dict,
                            "myself",
                        )
                        logging.debug(
                            'account="{}", connectivity_check="{}"'.format(
                                account, connectivity_check
                            )
                        )

                    except Exception as e:
                        logging.error(str(e))
                        raise Exception(str(e))

                    # Loop depending on the action, but do not fail here
                    try:

                        if self.opt == 1:
                            for project in self.get_jira_info(
                                jira_headers,
                                jira_url,
                                ssl_config,
                                proxy_dict,
                                "project",
                            ):
                                usercreds = {
                                    "_time": time.time(),
                                    "account": str(account),
                                    "key": project.get("key"),
                                    "key_projects": project.get("key")
                                    + " - "
                                    + project.get("name"),
                                }
                                yield usercreds

                        if self.opt == 2:
                            for issue in self.get_jira_info(
                                jira_headers,
                                jira_url,
                                ssl_config,
                                proxy_dict,
                                "issuetype",
                            ):
                                usercreds = {
                                    "_time": time.time(),
                                    "account": str(account),
                                    "issues": issue.get("name"),
                                }
                                yield usercreds

                        if self.opt == 3:
                            for priority in self.get_jira_info(
                                jira_headers,
                                jira_url,
                                ssl_config,
                                proxy_dict,
                                "priority",
                            ):
                                usercreds = {
                                    "_time": time.time(),
                                    "account": str(account),
                                    "priorities": priority.get("name"),
                                }
                                yield usercreds

                        if self.opt == 4:
                            for status in self.get_jira_info(
                                jira_headers, jira_url, ssl_config, proxy_dict, "status"
                            ):
                                result = {
                                    "_time": time.time(),
                                    "account": str(account),
                                    "status": status.get("name"),
                                    "statusCategory": status.get("statusCategory").get(
                                        "name"
                                    ),
                                }
                                yield result

                    except Exception as e:
                        logging.error(str(e))

        else:

            # account configuration
            isfound = False
            jira_ssl_certificate_validation = None
            jira_ssl_certificate_path = None
            username = None
            password = None

            conf_file = "ta_service_desk_simple_addon_account"
            confs = self.service.confs[str(conf_file)]
            for stanza in confs:

                if stanza.name == str(self.account):
                    isfound = True
                    for key, value in stanza.content.items():
                        if key == "jira_url":
                            jira_url = value
                        if key == "jira_ssl_certificate_validation":
                            jira_ssl_certificate_validation = value
                        if key == "jira_ssl_certificate_path":
                            jira_ssl_certificate_path = value
                        if key == "auth_type":
                            auth_type = value
                        if key == "jira_auth_mode":
                            jira_auth_mode = value
                        if key == "username":
                            username = value

            # end of get configuration

            # Stop here if we cannot find the submitted account
            if not isfound:
                raise ValueError(
                    "This acount has not been configured on this instance, cannot proceed!: %s",
                    self,
                )

            # else get the password
            else:
                credential_username = str(self.account) + "``splunk_cred_sep``1"
                credential_realm = "__REST_CREDENTIAL__#TA-jira-service-desk-simple-addon#configs/conf-ta_service_desk_simple_addon_account"
                for credential in storage_passwords:
                    if (
                        credential.content.get("username") == str(credential_username)
                        and credential.content.get("realm") == str(credential_realm)
                        and credential.content.get("clear_password").find("password")
                        > 0
                    ):
                        password = json.loads(
                            credential.content.get("clear_password")
                        ).get("password")
                        break

            # Build the authentication header for JIRA
            if str(jira_auth_mode) == "basic":
                authorization = username + ":" + password
                b64_auth = base64.b64encode(authorization.encode()).decode()
                jira_headers = {
                    "Authorization": "Basic %s" % b64_auth,
                    "Content-Type": "application/json",
                }
            elif str(jira_auth_mode) == "pat":
                jira_headers = {
                    "Authorization": "Bearer %s" % str(password),
                    "Content-Type": "application/json",
                }

            # Splunk Cloud vetting notes: SSL verification is always true or the path to the CA bundle for the SSL certificate to be verified
            if jira_ssl_certificate_path and os.path.isfile(jira_ssl_certificate_path):
                ssl_config = str(jira_ssl_certificate_path)
            else:
                ssl_config = True

            # test connectivity per account
            if self.opt == 0:

                try:
                    response = self.test_jira_connect(
                        self.account,
                        jira_headers,
                        jira_url,
                        ssl_config,
                        proxy_dict,
                        "myself",
                    )
                    response_dict = {
                        "account": self.account,
                        "connectivy_test": response.get("status"),
                        "response": response.get("response"),
                        "status_code": response.get("status_code"),
                    }

                    yield {
                        "_time": time.time(),
                        "_raw": response_dict,
                        "account": self.account,
                        "connectivy_test": response.get("status"),
                        "response": response.get("response"),
                        "status_code": response.get("status_code"),
                    }

                except Exception as e:

                    response_dict = {
                        "account": self.account,
                        "connectivy_test": "failure",
                        "exception": str(e),
                    }

                    yield {
                        "_time": time.time(),
                        "_raw": response_dict,
                        "account": self.account,
                        "connectivy_test": "failure",
                        "exception": str(e),
                    }

            else:

                # check connectivity and proceed
                try:

                    connectivity_check = self.test_jira_connect(
                        account,
                        jira_headers,
                        jira_url,
                        ssl_config,
                        proxy_dict,
                        "myself",
                    )
                    logging.debug(
                        'account="{}", connectivity_check="{}"'.format(
                            account, connectivity_check
                        )
                    )

                    if self.opt == 1:
                        for project in self.get_jira_info(
                            jira_headers, jira_url, ssl_config, proxy_dict, "project"
                        ):
                            usercreds = {
                                "_time": time.time(),
                                "account": str(self.account),
                                "key": project.get("key"),
                                "key_projects": project.get("key")
                                + " - "
                                + project.get("name"),
                            }
                            yield usercreds

                    if self.opt == 2:
                        for issue in self.get_jira_info(
                            jira_headers, jira_url, ssl_config, proxy_dict, "issuetype"
                        ):
                            usercreds = {
                                "_time": time.time(),
                                "account": str(self.account),
                                "issues": issue.get("name"),
                            }
                            yield usercreds

                    if self.opt == 3:
                        for priority in self.get_jira_info(
                            jira_headers, jira_url, ssl_config, proxy_dict, "priority"
                        ):
                            usercreds = {
                                "_time": time.time(),
                                "account": str(self.account),
                                "priorities": priority.get("name"),
                            }
                            yield usercreds

                    if self.opt == 4:
                        for status in self.get_jira_info(
                            jira_headers, jira_url, ssl_config, proxy_dict, "status"
                        ):
                            result = {
                                "_time": time.time(),
                                "account": str(self.account),
                                "status": status.get("name"),
                                "statusCategory": status.get("statusCategory").get(
                                    "name"
                                ),
                            }
                            yield result

                except Exception as e:
                    logging.error(str(e))
                    raise Exception(str(e))


dispatch(GenerateTextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
