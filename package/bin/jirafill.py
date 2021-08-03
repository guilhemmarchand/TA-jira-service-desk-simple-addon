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
import base64

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

    def get_jira_info(self, jira_headers, url, ssl_verify, proxy_dict , endpoint):
        response = requests.get(
            url=self.jira_url(url, endpoint),
            headers=jira_headers,
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

        # run
        if self.account == '_all':

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
                            if key == 'auth_type':
                                auth_type = value
                            if key == 'jira_auth_mode':
                                jira_auth_mode = value
                            if key == 'username':
                                username = value

                # end of get configuration

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

                if jira_ssl_certificate_validation:
                    if jira_ssl_certificate_validation == '0':
                        ssl_verify = False
                    elif jira_ssl_certificate_validation == '1' and jira_ssl_certificate_path and os.path.isfile(jira_ssl_certificate_path):
                        ssl_verify = str(jira_ssl_certificate_path)
                    elif jira_ssl_certificate_validation == '1':
                        ssl_verify = True

                if self.opt == 1:
                    for project in self.get_jira_info(jira_headers, jira_url, ssl_verify, proxy_dict ,'project'):
                        usercreds = {'_time': time.time(), 'account': str(account), 'key':project.get('key'), 'key_projects':project.get('key')+" - "+project.get('name')}
                        yield usercreds

                if self.opt == 2:
                    for issue in self.get_jira_info(jira_headers, jira_url, ssl_verify, proxy_dict , 'issuetype'):
                        usercreds = {'_time': time.time(), 'account': str(account), 'issues':issue.get('name')}
                        yield usercreds

                if self.opt == 3:
                    for priority in self.get_jira_info(jira_headers, jira_url, ssl_verify, proxy_dict , 'priority'):
                        usercreds = {'_time': time.time(), 'account': str(account), 'priorities':priority.get('name')}
                        yield usercreds

                if self.opt == 4:
                    for status in self.get_jira_info(jira_headers, jira_url, ssl_verify, proxy_dict , 'status'):
                        result = {'_time': time.time(), 'account': str(account), 'status':status.get('name'), 'statusCategory':status.get('statusCategory').get('name')}
                        yield result

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
                credential_username = str(self.account) + '``splunk_cred_sep``1'
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

            if jira_ssl_certificate_validation:
                if jira_ssl_certificate_validation == '0':
                    ssl_verify = False
                elif jira_ssl_certificate_validation == '1' and jira_ssl_certificate_path and os.path.isfile(jira_ssl_certificate_path):
                    ssl_verify = str(jira_ssl_certificate_path)
                elif jira_ssl_certificate_validation == '1':
                    ssl_verify = True

            if self.opt == 1:
                for project in self.get_jira_info(jira_headers, jira_url, ssl_verify, proxy_dict ,'project'):
                    usercreds = {'_time': time.time(), 'account': str(self.account), 'key':project.get('key'), 'key_projects':project.get('key')+" - "+project.get('name')}
                    yield usercreds

            if self.opt == 2:
                for issue in self.get_jira_info(jira_headers, jira_url, ssl_verify, proxy_dict , 'issuetype'):
                    usercreds = {'_time': time.time(), 'account': str(self.account), 'issues':issue.get('name')}
                    yield usercreds

            if self.opt == 3:
                for priority in self.get_jira_info(jira_headers, jira_url, ssl_verify, proxy_dict , 'priority'):
                    usercreds = {'_time': time.time(), 'account': str(self.account), 'priorities':priority.get('name')}
                    yield usercreds

            if self.opt == 4:
                for status in self.get_jira_info(jira_headers, jira_url, ssl_verify, proxy_dict , 'status'):
                    result = {'_time': time.time(), 'account': str(self.account), 'status':status.get('name'), 'statusCategory':status.get('statusCategory').get('name')}
                    yield result


dispatch(GenerateTextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
