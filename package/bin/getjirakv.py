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

splunkhome = os.environ['SPLUNK_HOME']
sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'TA-jira-service-desk-simple-addon', 'lib'))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import splunklib.client as client

@Configuration(distributed=False)

class GetJiraKv(GeneratingCommand):

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
            kvstore_instance = None
            bearer_token = None
            for stanza in confs:
                if stanza.name == "advanced_configuration":
                    for key, value in stanza.content.items():
                        if key == "jira_passthrough_mode":
                            jira_passthrough_mode = value
                        if key == "kvstore_instance":
                            kvstore_instance = value
                        if key == "bearer_token":
                            bearer_token = value
                        if key == "kvstore_search_filters":
                            kvstore_search_filters = value

            # the root search
            search = "| inputlookup jira_failures_replay | eval uuid=_key, mtime=if(isnull(mtime), ctime, mtime)"

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
