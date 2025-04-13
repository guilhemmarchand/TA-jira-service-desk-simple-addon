#!/usr/bin/env python
# coding=utf-8

import os
import sys
import time
import json
import logging
from logging.handlers import RotatingFileHandler
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = RotatingFileHandler(
    f"{splunkhome}/var/log/splunk/ta_jira_jsonexpand.log",
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

# import Splunk libs
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)
from splunklib import six
import splunklib.client as client
from ta_jira_libs import jira_get_conf


@Configuration()
class TrackMePrettyJson(StreamingCommand):

    input = Option(
        doc="""
        **Syntax:** **input=****
        **Description:** The fields containing the input to be expanded.""",
        require=False,
        default="_raw",
        validate=validators.Match("input", r"^.*$"),
    )

    subinput = Option(
        doc="""
        **Syntax:** **subinput=****
        **Description:** The fields containing the subinput to be expanded.""",
        require=False,
        default="issues",
        validate=validators.Match("subinput", r"^.*$"),
    )

    # status will be statically defined as imported

    def stream(self, records):

        # get conf
        jira_conf = jira_get_conf(
            self._metadata.searchinfo.session_key, self._metadata.searchinfo.splunkd_uri
        )

        # set loglevel
        log.setLevel(jira_conf["logging"]["loglevel"])

        # Loop, expand and yield
        count = 0

        for record in records:
            submainrecord = json.loads(record.get(self.input))
            logging.debug(f'subrecords="{submainrecord.get(self.subinput)}"')

            for subrecord in submainrecord.get(self.subinput):
                logging.debug(f'subrecord="{subrecord}"')
                count += 1

                try:

                    # yield
                    yield {
                        "_time": time.time(),
                        "_raw": json.dumps(subrecord, indent=2),
                    }

                    logging.info(
                        f'jirajsonexpand terminated successfully, results_count="{count}"'
                    )

                except Exception as e:
                    logging.error(
                        f'jirajsonexpand command failed with exception="{str(e)}"'
                    )
                    raise Exception(
                        f'jirajsonexpand command failed with exception="{str(e)}"'
                    )


dispatch(TrackMePrettyJson, sys.argv, sys.stdin, sys.stdout, __name__)
