#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

import json
import sys
import os
import splunk
import time
import requests
import logging
import base64
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ['SPLUNK_HOME']

# set logging
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/ta_jira_jirarest.log", 'a')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s')
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr,logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)      # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'TA-jira-service-desk-simple-addon', 'lib'))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators

# Import JIRA libs
from ta_jira_libs import test_jira_connect


@Configuration(distributed=False)
class GenerateTextCommand(GeneratingCommand):

    account = Option(
        doc='''
        **Syntax:** **account=****
        **Description:** JIRA account to be used, if unspecified the first account configured will be taken into account.''',
        require=False, default=None)
    method = Option(
        doc='''
        **Syntax:** **method=****
        **Description:** method to use for API target. DELETE GET POST PUT are supported.''',
        require=False, validate=validators.Match("method", r"^(DELETE|GET|POST|PUT)$"))
    json_request = Option(
        doc='''
        **Syntax:** **json_request=***JSON request*
        **Description:** JSON-formatted json_request.''',
        require=False, validate=validators.Match("json_request", r"^{.+}$"))
    target = Option(require=True)

    # Proceed
    def generate(self):

        storage_passwords = self.service.storage_passwords

        # global configuration
        conf_file = "ta_service_desk_simple_addon_settings"
        confs = self.service.confs[str(conf_file)]

        # set loglevel
        loglevel = 'INFO'
        for stanza in confs:
            if stanza.name == 'logging':
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        logginglevel = logging.getLevelName(loglevel)
        log.setLevel(logginglevel)

        # init
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
                credential_realm = '__REST_CREDENTIAL__#TA-jira-service-desk-simple-addon#configs/conf-ta_service_desk_simple_addon_settings'
                for credential in storage_passwords:
                    if credential.content.get('realm') == str(credential_realm) \
                        and credential.content.get('clear_password').find('proxy_password') > 0:
                        proxy_password = json.loads(credential.content.get('clear_password')).get('proxy_password')
                        break

                if proxy_type == 'http':
                    proxy_dict= {
                        "http" : "http://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port,
                        "https" : "https://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port
                        }
                else:
                    proxy_dict= {
                        "http" : str(proxy_type) + "://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port,
                        "https" : str(proxy_type) + "://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port
                        }

            else:
                proxy_dict= {
                    "http" : proxy_url + ":" + proxy_port,
                    "https" : proxy_url + ":" + proxy_port
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
            
        # define the account target
        if not self.account or self.account == '_any':
            account = str(accounts[0])
        else:
            account = str(self.account)

        # account configuration
        isfound = False
        jira_ssl_certificate_validation = None
        jira_ssl_certificate_path = None
        username = None
        password = None

        conf_file = "ta_service_desk_simple_addon_account"
        confs = self.service.confs[str(conf_file)]
        for stanza in confs:

            if stanza.name == str(account):
                isfound = True
                for key, value in stanza.content.items():
                    if key == "jira_url":
                        jira_url = value
                    if key == "jira_ssl_certificate_validation":
                        jira_ssl_certificate_validation = value
                    if key == "jira_ssl_certificate_path":
                        jira_ssl_certificate_path = value
                    if key == 'auth_type':
                        auth_type = value
                    if key == 'jira_auth_mode':
                        jira_auth_mode = value
                    if key == 'username':
                        username = value

        # end of get configuration

        # Stop here if we cannot find the submitted account
        if not isfound:
            self.logger.fatal('This acount has not been configured on this instance, cannot proceed!: %s', self)
            
        # else get the password
        else:
            credential_username = str(account) + '``splunk_cred_sep``1'
            credential_realm = '__REST_CREDENTIAL__#TA-jira-service-desk-simple-addon#configs/conf-ta_service_desk_simple_addon_account'
            for credential in storage_passwords:
                if credential.content.get('username') == str(credential_username) \
                    and credential.content.get('realm') == str(credential_realm) \
                    and credential.content.get('clear_password').find('password') > 0:
                    password = json.loads(credential.content.get('clear_password')).get('password')
                    break

            # Build the authentication header for JIRA
            if str(jira_auth_mode) == 'basic':
                authorization = username + ':' + password
                b64_auth = base64.b64encode(authorization.encode()).decode()
                jira_headers = {
                    'Authorization': 'Basic %s' % b64_auth,
                    'Content-Type': 'application/json',
                }
            elif str(jira_auth_mode) == 'pat':
                jira_headers = {
                    'Authorization': 'Bearer %s' % str(password),
                    'Content-Type': 'application/json',
                }

        # verify the url
        if not jira_url.startswith("https://"):
            jira_url = "https://" + str(jira_url)

        # handle SSL verification and bundle
        if jira_ssl_certificate_validation:
            if jira_ssl_certificate_validation == '0':
                ssl_verify = False
            elif jira_ssl_certificate_validation == '1' and jira_ssl_certificate_path and os.path.isfile(jira_ssl_certificate_path):
                ssl_verify = str(jira_ssl_certificate_path)
            elif jira_ssl_certificate_validation == '1':
                ssl_verify = True

        # verify the method
        if self.method:
            jira_method = self.method
        else:
            jira_method = "GET"

        if self.json_request:
            body_dict = json.loads(self.json_request)
        else:
            if jira_method == "POST" or jira_method == "PUT":
                raise Exception("jirarest: method {} requires a valid json_request. It is empty".format(jira_method))

        # check connectivity and proceed
        try:
            connectivity_check = test_jira_connect(account, jira_headers, jira_url, ssl_verify, proxy_dict)
            logging.debug("connectivity_check=\"{}\"".format(json.dumps(connectivity_check)))

            if self.target:
                # set proper headers
                if jira_method == "GET":
                    jira_fields_response = requests.get(
                        url=str(jira_url) + '/' + str(self.target),
                        headers=jira_headers,
                        verify=ssl_verify,
                        proxies=proxy_dict
                    )
                elif jira_method == "DELETE":
                    jira_fields_response = requests.delete(
                        url=str(jira_url) + '/' + str(self.target),
                        headers=jira_headers,
                        verify=ssl_verify,
                        proxies=proxy_dict
                    )
                elif jira_method == "POST":
                    jira_fields_response = requests.post(
                        url=str(jira_url) + '/' + str(self.target),
                        data=json.dumps(body_dict).encode('utf-8'),
                        headers=jira_headers,
                        verify=ssl_verify,
                        proxies=proxy_dict
                    )
                elif jira_method == "PUT":
                    jira_fields_response = requests.put(
                        url=str(jira_url) + '/' + str(self.target),
                        data=json.dumps(body_dict).encode('utf-8'),
                        headers=jira_headers,
                        verify=ssl_verify,
                        proxies=proxy_dict
                    )

                # Attenpt to get a JSON response, and render in Splunk
                try:

                    json_response = jira_fields_response.json()
                    data = {'_time': time.time(), '_raw': json.dumps(json_response)}
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
                        json_response = "{\"action\": \"" + str(response_action) + "\", \"status_code\": \"" + str(jira_fields_response.status_code) + "\", \"text\": \"" + str(jira_fields_response.text) + "\"}"
                    else:
                        json_response = "{\"action\": \"" + str(response_action) + "\", \"status_code\": \"" + str(jira_fields_response.status_code) + "\"}"
                    data = {'_time': time.time(), '_raw': str(json.dumps(json.loads(json_response, strict=False), indent=4))}

                    yield data

        except Exception as e:
            logging.error('JIRA connect verification failed for account=\"{}\" with exception=\"{}\"'.format(account, str(e)))
            raise Exception('JIRA connect verification failed for account=\"{}\" with exception=\"{}\"'.format(account, str(e)))

dispatch(GenerateTextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
