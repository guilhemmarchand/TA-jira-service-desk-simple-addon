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

import sys
import os
import splunk
import time
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json

@Configuration(distributed=False)
class GenerateTextCommand(GeneratingCommand):

    account = Option(require=True)
    opt = Option(require=True, validate=validators.Integer(0))

    def jira_url(self, url, endpoint):
        # For Splunk Cloud vetting, the URL must start with https://
        if not url.startswith("https://"):
            return 'https://%s/rest/api/latest/%s' % (url, endpoint)

        else:
            return '%s/rest/api/latest/%s' % (url, endpoint)

    def get_jira_info(self, username, password, url, ssl_verify, proxy_dict , endpoint):
        response = requests.get(
            url=self.jira_url(url, endpoint),
            auth=(username, password),
            verify=ssl_verify,
            proxies=proxy_dict
        )
        return response.json()

    def generate(self):
        storage_passwords = self.service.storage_passwords

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
                    if key == 'auth_type':
                        auth_type = value
                    if key == 'username':
                        username = value

        # global configuration
        conf_file = "ta_service_desk_simple_addon_settings"
        confs = self.service.confs[str(conf_file)]
        jira_passthrough_mode = None
        proxy_enabled = "0"
        proxy_url = None
        proxy_dict = None
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
        if proxy_enabled == "1":
           proxy_dict= {
              "http" : proxy_url + ":" + proxy_port,
              "https" : proxy_url + ":" + proxy_port
              }

        # end of get configuration

        # Stop here if we cannot find the submitted account
        if not isfound:
            self.logger.fatal('This acount has not been configured on this instance, cannot proceed!: %s', self)
        # else get the password
        else:
            credential_username = str(self.account) + '``splunk_cred_sep``1'
            credential_realm = '__REST_CREDENTIAL__#TA-jira-service-desk-simple-addon#configs/conf-ta_service_desk_simple_addon_account'
            for credential in storage_passwords:
                if credential.content.get('username') == str(credential_username) \
                    and credential.content.get('realm') == str(credential_realm) \
                    and credential.content.get('clear_password').find('password') > 0:
                    password = json.loads(credential.content.get('clear_password')).get('password')
                    break

        if jira_ssl_certificate_validation:
            if jira_ssl_certificate_validation == '0':
                ssl_verify = False
            elif jira_ssl_certificate_validation == '1' and jira_ssl_certificate_path and os.path.isfile(jira_ssl_certificate_path):
                ssl_verify = str(jira_ssl_certificate_path)
            elif jira_ssl_certificate_validation == '1':
                ssl_verify = True

        # debug
        self.logger.fatal('DEBUG!: %s', self)
        self.logger.fatal(str(jira_url))
        self.logger.fatal(str(username))
        self.logger.fatal(str(password))


        if self.opt == 1:
            for project in self.get_jira_info(username, password, jira_url, ssl_verify, proxy_dict ,'project'):
                usercreds = {'_time': time.time(), 'key':project.get('key'), 'key_projects':project.get('key')+" - "+project.get('name')}
                yield usercreds

        if self.opt == 2:
            for issue in self.get_jira_info(username, password, jira_url, ssl_verify, proxy_dict , 'issuetype'):
                usercreds = {'_time': time.time(), 'issues':issue.get('name')}
                yield usercreds

        if self.opt == 3:
            for priority in self.get_jira_info(username, password, jira_url, ssl_verify, proxy_dict , 'priority'):
                usercreds = {'_time': time.time(), 'priorities':priority.get('name')}
                yield usercreds

        if self.opt == 4:
            for status in self.get_jira_info(username, password, jira_url, ssl_verify, proxy_dict , 'status'):
                result = {'_time': time.time(), 'status':status.get('name'), 'statusCategory':status.get('statusCategory').get('name')}
                yield result

dispatch(GenerateTextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
