#!/usr/bin/env python
# coding=utf-8

# REST API SPL handler for JIRA, allows interracting with a remote Splunk KVstore instance
# See: https://ta-jira-service-desk-simple-addon.readthedocs.io/en/latest/

import os
import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import csv
import logging
from logging.handlers import RotatingFileHandler

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = RotatingFileHandler(
    f"{splunkhome}/var/log/splunk/ta_jira_getjirakv.log",
    mode="a",
    maxBytes=10000000,
    backupCount=1,
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)  # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

sys.path.append(
    os.path.join(splunkhome, "etc", "apps", "TA-jira-service-desk-simple-addon", "lib")
)

from splunklib.searchcommands import (
    dispatch,
    GeneratingCommand,
    Configuration,
    Option,
    validators,
)

# import least privileges access libs
from ta_jira_libs import jira_get_conf, jira_get_bearer_token


@Configuration(distributed=False)
class GetJiraKv(GeneratingCommand):

    verify = Option(
        doc="""
        **Syntax:** **verify=****
        **Description:** verify the connectivity to a remote instance. True / False are supported.""",
        require=False,
        default="False",
        validate=validators.Match("verify", r"^(True|False)$"),
    )

    def generate(self, **kwargs):

        if self:

            # Get the session key
            session_key = self._metadata.searchinfo.session_key
            server_uri = self._metadata.searchinfo.splunkd_uri
            # get conf
            jira_conf = jira_get_conf(
                self._metadata.searchinfo.session_key,
                self._metadata.searchinfo.splunkd_uri,
            )

            # set loglevel
            log.setLevel(jira_conf["logging"]["loglevel"])

            # init
            storage_passwords = self.service.storage_passwords
            jira_passthrough_mode = int(
                jira_conf["advanced_configuration"].get("jira_passthrough_mode", 0)
            )
            kvstore_instance = jira_conf["advanced_configuration"].get(
                "kvstore_instance", None
            )
            kvstore_search_filters = jira_conf["advanced_configuration"].get(
                "kvstore_search_filters", None
            )
            bearer_token = None

            if kvstore_instance:
                bearer_token = jira_get_bearer_token(session_key, server_uri)

            # the root search
            search = '| inputlookup jira_failures_replay | eval uuid=_key, mtime=if(isnull(mtime), ctime, mtime), status=case(isnull(status), "tempoary_failure", isnull(data), "tagged_for_removal", 1=1, status), data=if(isnull(data), "null", data), no_attempts=if(isnull(no_attempts), 0, no_attempts)'

            # If the passthrough mode is disabled, there is no distributed setup
            # and the instance is the localhost
            if (not kvstore_instance or not bearer_token) and str(
                jira_passthrough_mode
            ) == "0":
                kvstore_instance = self._metadata.searchinfo.splunkd_uri
                header = f"Splunk {session_key}"
            elif str(jira_passthrough_mode) == "1":
                # yield
                data = {
                    "_time": time.time(),
                    "_raw": f'{{"response": "INFO: Passthrough mode is currently enabled in this instance, you can safety disable the alert execution for this instance."}}',
                }
                yield data
                sys.exit(0)
            elif kvstore_instance and not bearer_token:
                # yield
                data = {
                    "_time": time.time(),
                    "_raw": f'{{"response": "ERROR: The KVstore instance is set but not the bearer token."}}',
                }
                yield data
                sys.exit(0)
            elif bearer_token and not kvstore_instance:
                # yield
                data = {
                    "_time": time.time(),
                    "_raw": f'{{"response": "ERROR: The bearer token is set but not the KVstore instance."}}',
                }
                yield data
                sys.exit(0)
            else:
                header = f"Bearer {bearer_token}"
                search = f"{search} | search {kvstore_search_filters}"

            # Define the url
            if not kvstore_instance.startswith("https://"):
                url = f"https://{kvstore_instance}/services/search/jobs/export"
            else:
                url = f"{kvstore_instance}/services/search/jobs/export"

            # Get data
            output_mode = "csv"
            exec_mode = "oneshot"

            # Call
            try:
                response = requests.post(
                    url,
                    headers={"Authorization": header},
                    verify=False,
                    data={
                        "search": search,
                        "output_mode": output_mode,
                        "exec_mode": exec_mode,
                    },
                )
                csv_data = response.text
                response.raise_for_status()

            except Exception as e:
                response_error = f"JIRA Get remove KVstore has failed!. url={url}, data={search}, HTTP Error={response.status_code}, content={response.text}"
                self.logger.fatal(str(response_error))
                data = {
                    "_time": time.time(),
                    "_raw": f'{{"response": "{response_error}"}}',
                }
                yield data
                sys.exit(0)

            if self.verify == "True":

                response_error = f"JIRA Get remove KVstore was successfull. url={url}, data={search}, HTTP Error={response.status_code}"
                data = {
                    "_time": time.time(),
                    "_raw": f'{{"response": "{response_error}"}}',
                }
                yield data
                sys.exit(0)

            else:

                # Use the CSV dict reader
                readCSV = csv.DictReader(
                    csv_data.splitlines(True),
                    delimiter=str(","),
                    quotechar=str('"'),
                )

                # For row in CSV, generate the _raw
                for row in readCSV:
                    yield {
                        "_time": time.time(),
                        "uuid": str(row["uuid"]),
                        "account": str(row["account"]),
                        "data": str(row["data"]),
                        "status": str(row["status"]),
                        "ctime": str(row["ctime"]),
                        "mtime": str(row["mtime"]),
                        "no_attempts": str(row["no_attempts"]),
                    }

        else:

            # yield
            data = {
                "_time": time.time(),
                "_raw": f'{{"response": "Error: bad request"}}',
            }
            yield data


dispatch(GetJiraKv, sys.argv, sys.stdin, sys.stdout, __name__)
