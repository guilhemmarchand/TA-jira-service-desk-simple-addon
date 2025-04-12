from __future__ import absolute_import, division, print_function, unicode_literals

__name__ = "jira_rest_handler.py"
__author__ = "Guilhem Marchand"

# Standard library imports
import json
import logging
import os
import sys
import time
from urllib.parse import urlencode
import urllib3

# Log level mapping
LOG_LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Third-party library imports
from logging.handlers import RotatingFileHandler

# splunk home
splunkhome = os.environ["SPLUNK_HOME"]

# set logging
logger = logging.getLogger(__name__)
filehandler = RotatingFileHandler(
    f"{splunkhome}/var/log/splunk/jira_service_desk_rest_api.log",
    mode="a",
    maxBytes=10000000,
    backupCount=1,
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
logging.Formatter.converter = time.gmtime
filehandler.setFormatter(formatter)
log = logging.getLogger()
for hdlr in log.handlers[:]:
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)
log.setLevel(logging.INFO)

# append lib
sys.path.append(
    os.path.join(splunkhome, "etc", "apps", "TA-jira-service-desk-simple-addon", "lib")
)

# import API handler
import jira_rest_handler

# import Splunk libs
import splunklib.client as client


class Jira_v1(jira_rest_handler.RESTHandler):
    def __init__(self, command_line, command_arg):
        super(Jira_v1, self).__init__(command_line, command_arg, logger)

    def get_get_conf(self, request_info, **kwargs):
        """
        This endpoint returns the local configuration of the app as a JSON object
        """

        describe = False

        # Retrieve from data
        try:
            resp_dict = json.loads(str(request_info.raw_args["payload"]))
        except Exception as e:
            resp_dict = None

        if resp_dict is not None:
            try:
                describe = resp_dict["describe"]
                if describe in ("true", "True"):
                    describe = True
            except Exception as e:
                describe = False
        else:
            # body is not required
            describe = False

        # if describe is requested, show the usage
        if describe:
            response = {
                "describe": "This endpoint retrieves and provide system wide configuration, it requires a GET call with no options:",
                "resource_desc": "Retrieve system wide configuration",
            }
            return {"payload": response, "status": 200}

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-jira-service-desk-simple-addon",
            port=request_info.server_rest_port,
            token=request_info.system_authtoken,
        )

        # set and get conf
        conf_file = "ta_service_desk_simple_addon_settings"
        confs = service.confs[str(conf_file)]

        # Initialize the jira_service_desk dictionary
        jira_service_desk = {}

        # Initialize timeout
        timeout = 30

        # Initialize the proxy-related variables
        proxy_enabled = "0"
        proxy_port = None
        proxy_type = None
        proxy_url = None
        proxy_username = None
        proxy_password = None
        proxy_dict = None

        # Get conf
        for stanza in confs:
            logging.debug(f'get_conf, Processing stanza.name="{stanza.name}"')
            # Create a sub-dictionary for the current stanza name if it doesn't exist
            if stanza.name not in jira_service_desk:
                jira_service_desk[stanza.name] = {}

            # Store key-value pairs from the stanza content in the corresponding sub-dictionary
            for stanzakey, stanzavalue in stanza.content.items():
                logging.debug(
                    f'get_get_conf, Processing stanzakey="{stanzakey}", stanzavalue="{stanzavalue}"'
                )
                jira_service_desk[stanza.name][stanzakey] = stanzavalue

                # Process the "proxy" stanza
                if stanza.name == "proxy":
                    if stanzakey == "proxy_enabled":
                        proxy_enabled = stanzavalue
                    elif stanzakey == "proxy_port":
                        proxy_port = stanzavalue
                    elif stanzakey == "proxy_type":
                        proxy_type = stanzavalue
                    elif stanzakey == "proxy_url":
                        proxy_url = stanzavalue
                    elif stanzakey == "proxy_username":
                        proxy_username = stanzavalue

                    # Process proxy settings
                    if proxy_enabled == "1":
                        # get proxy password
                        if proxy_username:
                            proxy_password = None

                            # get proxy password, if any
                            storage_passwords = service.storage_passwords
                            credential_realm = "__REST_CREDENTIAL__#TA-jira-service-desk-simple-addon#configs/conf-jira_service_desk_settings"
                            for credential in storage_passwords:
                                if (
                                    credential.content.get("realm")
                                    == str(credential_realm)
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
                                    "http": f"http://{proxy_username}:{proxy_password}@{proxy_url}:{proxy_port}",
                                    "https": f"https://{proxy_username}:{proxy_password}@{proxy_url}:{proxy_port}",
                                }
                            else:
                                proxy_dict = {
                                    "http": f"{proxy_type}://{proxy_username}:{proxy_password}@{proxy_url}:{proxy_port}",
                                    "https": f"{proxy_type}://{proxy_username}:{proxy_password}@{proxy_url}:{proxy_port}",
                                }

                        else:
                            proxy_dict = {
                                "http": f"{proxy_url}:{proxy_port}",
                                "https": f"{proxy_url}:{proxy_port}",
                            }

                    # add to the response
                    jira_service_desk["proxy"]["proxy_dict"] = proxy_dict

                # advanced configuration
                if stanza.name == "advanced_configuration":
                    if stanzakey == "timeout":
                        timeout = stanzavalue

                    # add to the response
                    jira_service_desk["advanced_configuration"]["timeout"] = int(
                        timeout
                    )

        # insert some useful additional information
        jira_service_desk["server_rest_uri"] = request_info.server_rest_uri
        jira_service_desk["server_rest_host"] = request_info.server_rest_host
        jira_service_desk["server_rest_port"] = request_info.server_rest_port

        logging.debug(f"get_get_conf, process result: {jira_service_desk}")

        return {"payload": jira_service_desk, "status": 200}

    # list accounts with least privileges approach
    def get_list_accounts(self, request_info, **kwargs):
        describe = False

        # Retrieve from data
        try:
            resp_dict = json.loads(str(request_info.raw_args["payload"]))
        except Exception as e:
            resp_dict = None

        if resp_dict is not None:
            try:
                describe = resp_dict["describe"]
                if describe in ("true", "True"):
                    describe = True
            except Exception as e:
                describe = False
        else:
            # body is required
            describe = False

        # if describe is requested, show the usage
        if describe:
            response = {
                "describe": "This endpoint lists all configured accounts, it requires a POST call with the following options:",
                "resource_desc": "Retrieve the list of accounts configured",
            }
            return {"payload": response, "status": 200}

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-jira-service-desk-simple-addon",
            port=request_info.server_rest_port,
            token=request_info.system_authtoken,
        )

        # set loglevel
        loglevel = "INFO"
        conf_file = "ta_service_desk_simple_addon_settings"
        confs = service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == "logging":
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        log.setLevel(loglevel)

        # get all acounts
        accounts = []
        conf_file = "ta_service_desk_simple_addon_account"
        confs = service.confs[str(conf_file)]
        for stanza in confs:
            # get all accounts
            for name in stanza.name:
                accounts.append(stanza.name)
                break

        # end of get configuration

        # Stop here if we cannot find the submitted account
        if len(accounts) == 0:
            return {
                "payload": {
                    "status": "failure",
                    "message": "There are no account configured yet for this instance.",
                },
                "status": 500,
            }

        else:
            #
            # response
            #

            return {"payload": {"accounts": accounts}, "status": 200}

    # get account details with least privileges approach
    def post_get_account(self, request_info, **kwargs):
        describe = False

        # Retrieve from data
        try:
            resp_dict = json.loads(str(request_info.raw_args["payload"]))
        except Exception as e:
            resp_dict = None

        if resp_dict is not None:
            try:
                describe = resp_dict["describe"]
                if describe in ("true", "True"):
                    describe = True
            except Exception as e:
                describe = False
                account = resp_dict["account"]
        else:
            # body is required
            describe = True

        # if describe is requested, show the usage
        if describe:
            response = {
                "describe": "This endpoint provides connectivity information, it requires a POST call with the following options:",
                "resource_desc": "Retrieve the account configuration",
                "options": [
                    {
                        "account": "The account configuration identifier",
                    }
                ],
            }
            return {"payload": response, "status": 200}

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-jira-service-desk-simple-addon",
            port=request_info.server_rest_port,
            token=request_info.system_authtoken,
        )

        # set loglevel
        loglevel = "INFO"
        conf_file = "ta_service_desk_simple_addon_settings"
        confs = service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == "logging":
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        log.setLevel(loglevel)

        # Splunk credentials store
        storage_passwords = service.storage_passwords

        # get all acounts
        accounts = []
        conf_file = "ta_service_desk_simple_addon_account"
        confs = service.confs[str(conf_file)]
        for stanza in confs:
            # get all accounts
            for name in stanza.name:
                accounts.append(stanza.name)
                break

        # Initialize a dictionary to store account data
        account_data = {
            "relay_account": None,
        }

        for stanza in confs:
            if stanza.name == str(account):
                for key, value in stanza.content.items():
                    account_data[key] = value
        logging.debug(f"account_data {account_data}")

        # Access variables using the dictionary
        jira_url = account_data["jira_url"]

        # end of get configuration

        # Stop here if we cannot find the submitted account
        if not account in accounts:
            return {
                "payload": {
                    "status": "failure",
                    "message": "The account could be found on this system, check the spelling and your configuration",
                    "account": account,
                },
                "status": 500,
            }

        elif len(accounts) == 0:
            return {
                "payload": {
                    "status": "failure",
                    "message": "There are no account configured yet for this instance.",
                    "account": account,
                },
                "status": 500,
            }

        else:
            # enforce https
            if not jira_url.startswith("https://"):
                jira_url = f"https://{str(jira_url)}"
                account_data["jira_url"] = jira_url

            # remote trailing slash in the URL, if any
            if jira_url.endswith("/"):
                jira_url = jira_url[:-1]
                account_data["jira_url"] = jira_url

            # get jira_password
            jira_password = None

            # realm
            credential_username = f"{str(account)}``splunk_cred_sep``1"
            credential_realm = "__REST_CREDENTIAL__#TA-jira-service-desk-simple-addon#configs/conf-ta_service_desk_simple_addon_account"

            for credential in storage_passwords:
                if credential.content.get("username") == str(
                    credential_username
                ) and credential.content.get("realm") == str(credential_realm):
                    jira_password = json.loads(
                        credential.content.get("clear_password")
                    ).get("password")
                    break

            #
            # verify and return the response
            #

            if not jira_password:
                msg = "The jira_password could not be retrieved, cannot continue."
                logging.error(msg)

                return {
                    "payload": {
                        "status": "failure",
                        "message": msg,
                        "account": account,
                    },
                    "status": 500,
                }

            else:
                # add the jira_password to a account_data and return it
                account_data["jira_password"] = jira_password

                return {"payload": account_data, "status": 200}
