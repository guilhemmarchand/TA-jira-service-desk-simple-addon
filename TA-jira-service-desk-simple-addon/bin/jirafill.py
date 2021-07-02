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

import ta_jira_service_desk_simple_addon_declare
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
        conf_file = "ta_jira_service_desk_simple_addon_settings"
        confs = self.service.confs[str(conf_file)]
        proxy_enabled = "0"
        proxy_url = None
        proxy_dict = None
        ssl_verify = False
        ssl_cert_path = None
        for stanza in confs:
            if stanza.name == "additional_parameters":
                for key, value in stanza.content.items():
                    if key == "jira_username":
                        username = value
                    if key == "jira_url":
                        url = value
                    if key == "jira_ssl_certificate_validation":
                        jira_ssl_certificate_validation = value
                    if key == "jira_ssl_certificate_path":
                        ssl_cert_path = value
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
        if jira_ssl_certificate_validation:
            if jira_ssl_certificate_validation == '0':
                ssl_verify = False
            elif jira_ssl_certificate_validation == '1' and ssl_cert_path and os.path.isfile(ssl_cert_path):
                ssl_verify = str(ssl_cert_path)
            elif jira_ssl_certificate_validation == '1':
                ssl_verify = True

        for credential in storage_passwords:
            if credential.content.get('username') == "additional_parameters``splunk_cred_sep``1" and credential.content.get('clear_password').find('jira_password') > 0:
                password = json.loads(credential.content.get('clear_password')).get('jira_password')
                break

        if self.opt == 1:
            for project in self.get_jira_info(username, password, url, ssl_verify, proxy_dict ,'project'):
                usercreds = {'_time': time.time(), 'key':project.get('key'), 'key_projects':project.get('key')+" - "+project.get('name')}
                yield usercreds

        if self.opt == 2:
            for issue in self.get_jira_info(username, password, url, ssl_verify, proxy_dict , 'issuetype'):
                usercreds = {'_time': time.time(), 'issues':issue.get('name')}
                yield usercreds

        if self.opt == 3:
            for priority in self.get_jira_info(username, password, url, ssl_verify, proxy_dict , 'priority'):
                usercreds = {'_time': time.time(), 'priorities':priority.get('name')}
                yield usercreds

        if self.opt == 4:
            for status in self.get_jira_info(username, password, url, ssl_verify, proxy_dict , 'status'):
                result = {'_time': time.time(), 'status':status.get('name'), 'statusCategory':status.get('statusCategory').get('name')}
                yield result

dispatch(GenerateTextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
