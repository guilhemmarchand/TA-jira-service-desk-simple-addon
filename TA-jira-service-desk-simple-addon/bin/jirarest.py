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
        conf_file = "ta_jira_service_desk_simple_addon_settings"
        confs = self.service.confs[str(conf_file)]
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
        if proxy_url:
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

        if not url.startswith("https://"):
            url = "https://" + str(url)

        for credential in storage_passwords:
            if credential.content.get('username') == "additional_parameters``splunk_cred_sep``1" and credential.content.get('clear_password').find('jira_password') > 0:
                password = json.loads(credential.content.get('clear_password')).get('jira_password')
                break

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
                    url=str(url) + '/' + str(self.target),
                    auth=(username, password),
                    verify=ssl_verify,
                    proxies=proxy_dict
                )
            elif jira_method == "DELETE":
                jira_fields_response = requests.delete(
                    url=str(url) + '/' + str(self.target),
                    auth=(username, password),
                    verify=ssl_verify,
                    proxies=proxy_dict
                )
            elif jira_method == "POST":
                jira_fields_response = requests.post(
                    headers=headers,
                    url=str(url) + '/' + str(self.target),
                    data=json.dumps(body_dict).encode('utf-8'),
                    auth=(username, password),
                    verify=ssl_verify,
                    proxies=proxy_dict
                )
            elif jira_method == "PUT":
                jira_fields_response = requests.put(
                    headers=headers,
                    url=str(url) + '/' + str(self.target),
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
