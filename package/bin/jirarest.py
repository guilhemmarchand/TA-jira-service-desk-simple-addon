#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2011-2015 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, unicode_literals

import import_declare_test
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators

import json
import sys
import os
import splunk
import time
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

    def jira_url(self, url, endpoint):
        # For Splunk Cloud vetting, the URL must start with https://
        if not url.startswith("https://"):
            return 'https://%s/rest/api/latest/%s' % (url, endpoint)
        else:
            return '%s/rest/api/latest/%s' % (url, endpoint)

    def get_jira_info(self, username, password, url, ssl_verify, proxy_dict, endpoint):
        response = requests.get(
            url=self.jira_url(url, endpoint),
            auth=(username, password),
            verify=ssl_verify,
            proxies=proxy_dict
        )
        return response.json()

    def generate(self):
        storage_passwords = self.service.storage_passwords

        # global configuration
        conf_file = "ta_service_desk_simple_addon_settings"
        confs = self.service.confs[str(conf_file)]
        jira_passthrough_mode = None
        proxy_enabled = "0"
        proxy_url = None
        proxy_dict = None
        proxy_username = None
        for stanza in confs:
            if stanza.name == "advanced_configuration":
                for key, value in stanza.content.items():
                    if key == "jira_passthrough_mode":
                        jira_passthrough_mode = value
            if stanza.name == "proxy":
                for key, value in stanza.content.items():
                    if key == "proxy_enabled":
                        proxy_enabled = value
                    if key == "proxy_port":
                        proxy_port = value
                    if key == "proxy_rdns":
                        proxy_rdns = value
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

        if self.target:
            # set proper headers
            headers = {'Content-type': 'application/json'}
            if jira_method == "GET":
                jira_fields_response = requests.get(
                    url=str(jira_url) + '/' + str(self.target),
                    auth=(username, password),
                    verify=ssl_verify,
                    proxies=proxy_dict
                )
            elif jira_method == "DELETE":
                jira_fields_response = requests.delete(
                    url=str(jira_url) + '/' + str(self.target),
                    auth=(username, password),
                    verify=ssl_verify,
                    proxies=proxy_dict
                )
            elif jira_method == "POST":
                jira_fields_response = requests.post(
                    headers=headers,
                    url=str(jira_url) + '/' + str(self.target),
                    data=json.dumps(body_dict).encode('utf-8'),
                    auth=(username, password),
                    verify=ssl_verify,
                    proxies=proxy_dict
                )
            elif jira_method == "PUT":
                jira_fields_response = requests.put(
                    headers=headers,
                    url=str(jira_url) + '/' + str(self.target),
                    data=json.dumps(body_dict).encode('utf-8'),
                    auth=(username, password),
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

dispatch(GenerateTextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
