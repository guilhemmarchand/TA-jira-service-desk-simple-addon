#!/usr/bin/env python
# coding=utf-8

# REST API SPL handler for JIRA, allows interracting with a remote Splunk KVstore instance
# See: https://ta-jira-service-desk-simple-addon.readthedocs.io/en/latest/

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import splunk
import splunk.entity
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import csv
import logging
import re

splunkhome = os.environ['SPLUNK_HOME']

# set logging
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/ta_jira_getjirakv.log", 'a')
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
import splunklib.client as client

@Configuration(distributed=False)

class GetJiraKv(GeneratingCommand):

    verify = Option(
        doc='''
        **Syntax:** **verify=****
        **Description:** verify the connectivity to a remote instance. True / False are supported.''',
        require=False, default="False", validate=validators.Match("verify", r"^(True|False)$"))

    def generate(self, **kwargs):

        if self:

            # Get the session key
            session_key = self._metadata.searchinfo.session_key

            # Get splunkd port
            entity = splunk.entity.getEntity('/server', 'settings',
                                                namespace='TA-jira-service-desk-simple-addon', sessionKey=session_key, owner='-')
            splunkd_port = entity['mgmtHostPort']

            # Get conf
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
            storage_passwords = self.service.storage_passwords
            kvstore_instance = None
            bearer_token = None
            for stanza in confs:
                if stanza.name == "advanced_configuration":
                    for key, value in stanza.content.items():
                        if key == "jira_passthrough_mode":
                            jira_passthrough_mode = value
                        if key == "kvstore_instance":
                            kvstore_instance = value
                        if key == "kvstore_search_filters":
                            kvstore_search_filters = value

            if kvstore_instance:

                # The bearer token is stored in the credential store
                # However, likely due to the number of chars, the credential.content.get SDK command is unable to return its value in a single operation
                # As a workaround, we concatenate the different values return to form a complete object, finally we use a regex approach to extract its clear text value
                credential_realm = '__REST_CREDENTIAL__#TA-jira-service-desk-simple-addon#configs/conf-ta_service_desk_simple_addon_settings'
                bearer_token_rawvalue = ""

                for credential in storage_passwords:
                    if credential.content.get('realm') == str(credential_realm):
                        bearer_token_rawvalue = bearer_token_rawvalue + str(credential.content.clear_password)

                # extract a clean json object
                bearer_token_rawvalue_match = re.search('\{\"bearer_token\":\s*\"(.*)\"\}', bearer_token_rawvalue)
                if bearer_token_rawvalue_match:
                    bearer_token = bearer_token_rawvalue_match.group(1)
                else:
                    bearer_token = None

            # the root search
            search = "| inputlookup jira_failures_replay | eval uuid=_key, mtime=if(isnull(mtime), ctime, mtime), status=case(isnull(status), \"tempoary_failure\", isnull(data), \"tagged_for_removal\", 1=1, status), data=if(isnull(data), \"null\", data), no_attempts=if(isnull(no_attempts), 0, no_attempts)"

            # If the passthrough mode is disabled, there is no distributed setup
            # and the instance is the localhost
            if (not kvstore_instance or not bearer_token) and str(jira_passthrough_mode) == '0':
                kvstore_instance = 'localhost:' + str(splunkd_port)
                header = 'Splunk ' + str(session_key)
            elif str(jira_passthrough_mode) == '1':
                # yield
                data = {'_time': time.time(), '_raw': "{\"response\": \"" + "INFO: Passthrough mode is currently enabled in this instance, you can safety disable the alert execution for this instance.}"}
                yield data
                sys.exit(0)
            elif kvstore_instance and not bearer_token:
                # yield
                data = {'_time': time.time(), '_raw': "{\"response\": \"" + "ERROR: The KVstore instance is set but not the bearer token.}"}
                yield data
                sys.exit(0)
            elif bearer_token and not kvstore_instance:
                # yield
                data = {'_time': time.time(), '_raw': "{\"response\": \"" + "ERROR: The bearer token is set but not the KVstore instance.}"}
                yield data
                sys.exit(0)
            else:
                header = 'Bearer ' + str(bearer_token)
                search = str(search) + " | search " + str(kvstore_search_filters)

            # Define the url
            url = "https://" + str(kvstore_instance) + "/services/search/jobs/export"

            # Get data
            output_mode = "csv"
            exec_mode = "oneshot"
            response = requests.post(url, headers={'Authorization': header}, verify=False, data={'search': search, 'output_mode': output_mode, 'exec_mode': exec_mode}) 
            csv_data = response.text

            if response.status_code not in (200, 201, 204):
                response_error = 'JIRA Get remove KVstore has failed!. url={}, data={}, HTTP Error={}, content={}'.format(url, search, response.status_code, response.text)
                self.logger.fatal(str(response_error))
                data = {'_time': time.time(), '_raw': "{\"response\": \"" + str(response_error) + "\""}
                yield data
                sys.exit(0)

            else:

                if self.verify == 'True':

                    response_error = 'JIRA Get remove KVstore was successfull. url={}, data={}, HTTP Error={}'.format(url, search, response.status_code)
                    data = {'_time': time.time(), '_raw': "{\"response\": \"" + str(response_error) + "\""}
                    yield data
                    sys.exit(0)

                else:

                    # Use the CSV dict reader
                    readCSV = csv.DictReader(csv_data.splitlines(True), delimiter=str(u','), quotechar=str(u'"'))

                    # For row in CSV, generate the _raw
                    for row in readCSV:
                        yield {'_time': time.time(), 'uuid': str(row['uuid']), 'account': str(row['account']), 'data': str(row['data']), 'status': str(row['status']), 'ctime': str(row['ctime']), 'mtime': str(row['mtime']), 'no_attempts': str(row['no_attempts'])}

        else:

            # yield
            data = {'_time': time.time(), '_raw': "{\"response\": \"" + "Error: bad request}"}
            yield data

dispatch(GetJiraKv, sys.argv, sys.stdin, sys.stdout, __name__)
