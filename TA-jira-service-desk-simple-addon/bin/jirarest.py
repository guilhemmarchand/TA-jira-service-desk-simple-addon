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
import splunk
import time
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json

@Configuration(distributed=False)
class GenerateTextCommand(GeneratingCommand):

    target = Option(require=True)

    def jira_url(self, url, endpoint):
        # For Splunk Cloud vetting, the URL must start with https://
        if not url.startswith("https://"):
            return 'https://%s/rest/api/latest/%s' % (url, endpoint)
        else:
            return '%s/rest/api/latest/%s' % (url, endpoint)

    def get_jira_info(self, username, password, url, endpoint):
        response = requests.get(
            url=self.jira_url(url, endpoint),
            auth=(username, password),
            verify=False
        )
        return response.json()

    def generate(self):
        storage_passwords = self.service.storage_passwords
        conf_file = "ta_jira_service_desk_simple_addon_settings"
        confs = self.service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == "additional_parameters":
                for key, value in stanza.content.items():
                    if key == "jira_username":
                        username = value
                    if key == "jira_url":
                        url = value

        for credential in storage_passwords:
            if credential.content.get('username') == "additional_parameters``splunk_cred_sep``1" and credential.content.get('clear_password').find('jira_password') > 0:
                password = json.loads(credential.content.get('clear_password')).get('jira_password')
                break

        if self.target:

                if not url.startswith("https://"):
                    jira_fields_response = requests.get(
                        url="https://" + str(url) + '/' + str(self.target),
                        auth=(username, password),
                        verify=False
                    )
                else:
                    jira_fields_response = requests.get(
                        url=str(url) + '/' + str(self.target),
                        auth=(username, password),
                        verify=False
                    )

                data = {'_time': time.time(), '_raw': json.dumps(jira_fields_response.json())}
                yield data

dispatch(GenerateTextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
