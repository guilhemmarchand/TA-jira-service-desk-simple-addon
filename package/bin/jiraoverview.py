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

splunkhome = os.environ['SPLUNK_HOME']

# set logging
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/ta_jira_jiraoverview.log", 'a')
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

        # loop through the accounts
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

            # verify the url
            if not jira_url.startswith("https://"):
                jira_url = "https://" + str(jira_url)

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

            # ensures connectivity and proceed
            try:
                connectivity_check = test_jira_connect(account, jira_headers, jira_url, ssl_verify, proxy_dict)
                logging.debug('account=\"{}\", connectivity_check=\"{}\"'.format(account, connectivity_check))

            except Exception as e:
                logging.error(str(e))
                raise Exception(str(e))

            # Get the list of projects
            projects_list = []
            jira_check_url = jira_url + '/rest/api/latest/project'
            try:
                response = requests.get(
                    url=jira_check_url,
                    headers=jira_headers,
                    verify=ssl_verify,
                    proxies=proxy_dict,
                    timeout=10,
                )
                if response.status_code not in (200, 201, 204):
                    raise Exception(
                        'JIRA operation failed, account=\"{}\", url=\"{}\", HTTP Error=\"{}\", HTTP Response=\"{}\"'.format(account, jira_check_url, response.status_code, response.text))
                else:
                    logging.debug(response.text)

                    for project_response in json.loads(response.text):
                        projects_list.append(project_response.get('key'))

                logging.debug("list of projects=\"{}\"".format(projects_list))

            except Exception as e:
                logging.error('JIRA operation failed for account=\"{}\" with exception=\"{}\"'.format(account, str(e)))
                raise Exception('JIRA operation failedfor account=\"{}\" with exception=\"{}\"'.format(account, str(e)))

            # Loop through the projects, and return the KPIs
            for project in projects_list:

                # total count of issues
                jira_check_url = jira_url + '/rest/api/latest/search?jql=project=' + project + '&maxResults=0'
                try:
                    response = requests.get(
                        url=jira_check_url,
                        headers=jira_headers,
                        verify=ssl_verify,
                        proxies=proxy_dict,
                        timeout=10,
                    )
                    if response.status_code not in (200, 201, 204):
                        logging.error('JIRA operation failed for account=\"{}\" with exception=\"{}\"'.format(account, str(e)))
                    else:
                        logging.debug(response.text)

                        yield_dict = {
                            'account': account,
                            'project': project,
                            'type': 'total_issues',
                            'value': json.loads(response.text).get('total'),
                        }

                        yield {
                            '_time': time.time(),
                            '_raw': yield_dict,
                            'account': account,
                            'project': project,
                            'type': 'total_issues',
                            'value': json.loads(response.text).get('total'),
                        }

                except Exception as e:
                    logging.error('JIRA operation failed for account=\"{}\" with exception=\"{}\"'.format(account, str(e)))

                # total done
                jira_check_url = jira_url + '/rest/api/latest/search?jql=project=' + project + '%20AND%20statuscategory%20IN%20%28%22Done%22%29&maxResults=0'
                try:
                    response = requests.get(
                        url=jira_check_url,
                        headers=jira_headers,
                        verify=ssl_verify,
                        proxies=proxy_dict,
                        timeout=10,
                    )
                    if response.status_code not in (200, 201, 204):
                        logging.error('JIRA operation failed for account=\"{}\" with exception=\"{}\"'.format(account, str(e)))
                    else:
                        logging.debug(response.text)

                        yield_dict = {
                            'account': account,
                            'project': project,
                            'type': 'total_done',
                            'value': json.loads(response.text).get('total'),
                        }

                        yield {
                            '_time': time.time(),
                            '_raw': yield_dict,
                            'account': account,
                            'project': project,
                            'type': 'total_done',
                            'value': json.loads(response.text).get('total'),
                        }

                except Exception as e:
                    logging.error('JIRA operation failed for account=\"{}\" with exception=\"{}\"'.format(account, str(e)))

                # total todo
                jira_check_url = jira_url + '/rest/api/latest/search?jql=project=' + project + '%20AND%20statuscategory%20IN%20%28%22To%20Do%22%29&maxResults=0'
                try:
                    response = requests.get(
                        url=jira_check_url,
                        headers=jira_headers,
                        verify=ssl_verify,
                        proxies=proxy_dict,
                        timeout=10,
                    )
                    if response.status_code not in (200, 201, 204):
                        logging.error('JIRA operation failed for account=\"{}\" with exception=\"{}\"'.format(account, str(e)))
                    else:
                        logging.debug(response.text)

                        yield_dict = {
                            'account': account,
                            'project': project,
                            'type': 'total_to_do',
                            'value': json.loads(response.text).get('total'),
                        }

                        yield {
                            '_time': time.time(),
                            '_raw': yield_dict,
                            'account': account,
                            'project': project,
                            'type': 'total_to_do',
                            'value': json.loads(response.text).get('total'),
                        }

                except Exception as e:
                    logging.error('JIRA operation failed for account=\"{}\" with exception=\"{}\"'.format(account, str(e)))

                # total todo
                jira_check_url = jira_url + '/rest/api/latest/search?jql=project=' + project + '%20AND%20statuscategory%20IN%20%28%22In%20Progress%22%29&maxResults=0'
                try:
                    response = requests.get(
                        url=jira_check_url,
                        headers=jira_headers,
                        verify=ssl_verify,
                        proxies=proxy_dict,
                        timeout=10,
                    )
                    if response.status_code not in (200, 201, 204):
                        logging.error('JIRA operation failed for account=\"{}\" with exception=\"{}\"'.format(account, str(e)))
                    else:
                        logging.debug(response.text)

                        yield_dict = {
                            'account': account,
                            'project': project,
                            'type': 'total_in_progress',
                            'value': json.loads(response.text).get('total'),
                        }

                        yield {
                            '_time': time.time(),
                            '_raw': yield_dict,
                            'account': account,
                            'project': project,
                            'type': 'total_in_progress',
                            'value': json.loads(response.text).get('total'),
                        }

                except Exception as e:
                    logging.error('JIRA operation failed for account=\"{}\" with exception=\"{}\"'.format(account, str(e)))

dispatch(GenerateTextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
