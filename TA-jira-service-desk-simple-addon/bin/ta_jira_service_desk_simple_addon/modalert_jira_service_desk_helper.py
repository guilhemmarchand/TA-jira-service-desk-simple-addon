# encoding = utf-8

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example gets and sets the log level
    helper.set_log_level(helper.log_level)

    # The following example gets the setup parameters and prints them to the log
    jira_url = helper.get_global_setting("jira_url")
    helper.log_info("jira_url={}".format(jira_url))
    jira_username = helper.get_global_setting("jira_username")
    helper.log_info("jira_username={}".format(jira_username))
    jira_password = helper.get_global_setting("jira_password")
    helper.log_info("jira_password={}".format(jira_password))
    jira_ssl_certificate_validation = helper.get_global_setting("jira_ssl_certificate_validation")
    helper.log_info("jira_ssl_certificate_validation={}".format(jira_ssl_certificate_validation))

    # The following example gets the alert action parameters and prints them to the log
    jira_project = helper.get_param("jira_project")
    helper.log_info("jira_project={}".format(jira_project))

    jira_issue_type = helper.get_param("jira_issue_type")
    helper.log_info("jira_issue_type={}".format(jira_issue_type))

    jira_priority = helper.get_param("jira_priority")
    helper.log_info("jira_priority={}".format(jira_priority))

    jira_priority_dynamic = helper.get_param("jira_priority_dynamic")
    helper.log_info("jira_priority_dynamic={}".format(jira_priority_dynamic))

    jira_labels = helper.get_param("jira_labels")
    helper.log_info("jira_labels={}".format(jira_labels))

    jira_summary = helper.get_param("jira_summary")
    helper.log_info("jira_summary={}".format(jira_summary))

    jira_description = helper.get_param("jira_description")
    helper.log_info("jira_description={}".format(jira_description))

    jira_assignee = helper.get_param("jira_assignee")
    helper.log_info("jira_assignee={}".format(jira_assignee))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    # TODO: Implement your alert action logic here
    #query the url from setup

    helper.set_log_level(helper.log_level)
    helper.log_info("Alert action jira_service_desk started.")

    # Retrieve JIRA connnection parameters and settings
    jira_url = helper.get_global_setting("jira_url")
    helper.log_debug("jira_url={}".format(jira_url))
    
    jira_username = helper.get_global_setting("jira_username")
    helper.log_debug("jira_username={}".format(jira_username))

    jira_password = helper.get_global_setting("jira_password")
    #helper.log_debug("jira_password={}".format(jira_password))
    
    jira_ssl_certificate_validation = helper.get_global_setting("jira_ssl_certificate_validation")
    if jira_ssl_certificate_validation == 0:
        ssl_certificate_validation = False
    elif jira_ssl_certificate_validation == 1:
        ssl_certificate_validation = True
    else:
        ssl_certificate_validation = True

    helper.log_debug("jira_ssl_certificate_validation={}".format(ssl_certificate_validation))

    #call the query URL REST Endpoint and pass the url and API token
    content = query_url(helper, jira_url, jira_username, jira_password, ssl_certificate_validation)  

    #write the response returned by Virus Total API to splunk index
    #helper.addevent(content, sourcetype="VirusTotal")
    #helper.writeevents(index="main", host="localhost", source="VirusTotal")    

    # Retrieve parameters
    jira_project = helper.get_param("jira_project")
    jira_issue_type = helper.get_param("jira_issue_type")
    jira_priority = helper.get_param("jira_priority")
    jira_priority_dynamic = helper.get_param("jira_priority_dynamic")
    jira_summary = helper.get_param("jira_summary")
    jira_description = helper.get_param("jira_description")
    jira_assignee = helper.get_param("jira_assignee")

    return 0


# This function is required to prevent any failure due to content which we have no control on
def checkstr(i):

    if i is not None:
        i = i.replace("\\", "\\\\")
        # Manage line breaks
        i = i.replace("\n", "\\n")
        i = i.replace("\r", "\\r")
        # Manage tabs
        i = i.replace("\t", "\\t")
        # Manage breaking delimiters
        i = i.replace("\"", "\\\"")
        return i


# This function is required to reformat proper values in the custom fields
def reformat_customfields(i):

    import re

    if i is not None:
        i = re.sub(r'\\"customfield_(\d+)\\": \\"', r'"customfield_\1": "', i)
        i = re.sub(r'\\"customfield_(\d+)\\": (\d)', r'"customfield_\1": \2', i)
        i = re.sub(r'\\"customfield_(\d+)\\": {', r'"customfield_\1": {', i)
        i = re.sub(r'\\"customfield_(\d+)\\": \[', r'"customfield_\1": \[', i)
        i = re.sub(r'\\",\\n', '",\n', i)
        i = re.sub(r'\{\\"value\\": \\"', '{"value": "', i)
        i = re.sub(r'\\\[ {\\"value\\": "', '[ {"value": "', i)
        i = re.sub(r'\\\[{\\"value\\": "', '[{"value": "', i)
        i = re.sub(r'\\\[ {"value": "', '[ {"value": "', i)
        i = re.sub(r'\\\[{"value": "', '[{"value": "', i)
        i = re.sub(r'\\"}', '"}', i)
        i = re.sub(r'\\" }', '" }', i)
        i = re.sub(r'\\" }]', '" }]', i)
        i = re.sub(r',\\n"customfield', ',\n"customfield', i)
        i = re.sub(r"\\\"$", "\"", i)
        i = re.sub(r"\\\"\,$", "\"", i)
        i = re.sub(r"\\\"\\n$", "\"", i)
        i = re.sub(r"\\\"\,\\n$", "\"", i)
        i = re.sub(r"(\d*),$", r"\1", i)
        i = re.sub(r"(\d*),\\n$", r"\1", i)
        i = re.sub(r"(\d*)\\n$", r"\1", i)
        # generic replacement
        i = re.sub(r'\\\"(\w*)\\\":\s\\\"([^\"]*)\"', r'"\1": "\2"', i)


        return i


def query_url(helper, jira_url, jira_username, jira_password, ssl_certificate_validation):

    import requests
    import json
    import os
    import uuid
    import sys
    import time
    import base64

    import splunk.entity
    import splunk.Intersplunk

    # Retrieve the session_key
    helper.log_debug("Get session_key.")
    session_key = helper.session_key

    # Get splunkd port
    entity = splunk.entity.getEntity('/server', 'settings',
                                     namespace='TA-jira-service-desk-simple-addon', sessionKey=session_key, owner='-')
    mydict = entity
    splunkd_port = mydict['mgmtHostPort']
    helper.log_debug("splunkd_port={}".format(splunkd_port))

    # Build the jira_url and enforce https
    if 'https://' not in jira_url:
        jira_url = 'https://' + jira_url + '/rest/api/2/issue'
    else:
        jira_url = jira_url + '/rest/api/2/issue'

    # get proxy configuration
    proxy_config = helper.get_proxy()
    proxy_url = proxy_config.get("proxy_url")
    helper.log_debug("proxy_url={}".format(proxy_url))

    if proxy_url is not None:
        opt_use_proxy = True
        helper.log_debug("use_proxy set to True")
    else:
        opt_use_proxy = False
        helper.log_debug("use_proxy set to False")

    # Retrieve parameters which are not event related
    jira_project = helper.get_param("jira_project")
    jira_project = checkstr(jira_project)
    helper.log_debug("jira_project={}".format(jira_project))

    jira_issue_type = helper.get_param("jira_issue_type")
    jira_issue_type = checkstr(jira_issue_type)
    helper.log_debug("jira_issue_type={}".format(jira_issue_type))

    jira_priority = helper.get_param("jira_priority")
    jira_priority = checkstr(jira_priority)
    helper.log_debug("jira_priority={}".format(jira_priority))

    # Build the header including basic auth
    authorization = jira_username + ':' + jira_password
    b64_auth = base64.b64encode(authorization.encode()).decode()
    headers = {
        'Authorization': 'Basic %s' % b64_auth,
        'Content-Type': 'application/json',
    }

    # Loop within events and proceed
    events = helper.get_events()
    for event in events:
        helper.log_debug("event={}".format(event))

        jira_priority_dynamic = helper.get_param("jira_priority_dynamic")
        jira_priority_dynamic = checkstr(jira_priority_dynamic)
        helper.log_debug("jira_priority_dynamic={}".format(jira_priority_dynamic))

        jira_summary = helper.get_param("jira_summary")
        jira_summary = checkstr(jira_summary)
        helper.log_debug("jira_summary={}".format(jira_summary))

        jira_description = helper.get_param("jira_description")
        jira_description = checkstr(jira_description)
        helper.log_debug("jira_description={}".format(jira_description))

        jira_assignee = helper.get_param("jira_assignee")
        jira_assignee = checkstr(jira_assignee)
        helper.log_debug("jira_assignee={}".format(jira_assignee))

        jira_labels = helper.get_param("jira_labels")
        jira_labels = checkstr(jira_labels)
        helper.log_debug("jira_labels={}".format(jira_labels))

        # Retrieve the custom fields
        jira_customfields = helper.get_param("jira_customfields")
        jira_customfields = checkstr(jira_customfields)
        jira_customfields = reformat_customfields(jira_customfields)
        helper.log_debug("jira_customfields={}".format(jira_customfields))

        # Manage custom fields properly
        data = '{\n' + '"fields": {\n' + '"project":\n {\n"key": "' + jira_project + '"' + '\n },\n"summary": "' \
               + jira_summary + '",\n"description": "' + jira_description + '",\n"issuetype": {\n"name": "' \
               + jira_issue_type + '"\n}'

        if jira_assignee not in ["", "None", None]:
            data = data + ',\n "assignee" : {\n' + '"name": "' + jira_assignee + '"\n }'

        # Priority can be dynamically overridden by the text input dynamic priority, if set
        if jira_priority not in ["", "None", None]:
            if jira_priority_dynamic is not None:
                helper.log_debug("jira priority is overridden by "
                                 "jira_priority_dynamic={}".format(jira_priority_dynamic))
                data = data + ',\n "priority" : {\n' + '"name": "' + jira_priority_dynamic + '"\n }'
            else:
                data = data + ',\n "priority" : {\n' + '"name": "' + jira_priority + '"\n }'

        if jira_labels not in ["", "None", None]:
            jira_labels = jira_labels.split(",")
            altered = map(lambda x: '\"%s\"' % x, jira_labels)
            jira_labels = " [ "+",".join(altered) + " ]"
            data = data + ',\n "labels" :' + jira_labels

        # JIRA custom fields structure
        if jira_customfields not in ["", "None", None]:
            data = data + ',\n ' + jira_customfields + '\n'

        # Finally close
        data = data + '\n}\n}'

        # log raw json in debug mode
        helper.log_debug("json raw data for final rest call before json.loads:={}".format(data))

        # Properly load json
        try:
            data = json.dumps(json.loads(data, strict=False), indent=4)
        except Exception as e:
            helper.log_error("json loads failed to accept some of the characters,"
                             " raw json data before json.loads:={}".format(data))
            raise e

        # log json in debug mode
        helper.log_debug("json data for final rest call:={}".format(data))

        # Try http post, catch exceptions and incorrect http return codes
        try:
            response = helper.send_http_request(jira_url, "POST", parameters=None, payload=data,
                                                headers=headers, cookies=None, verify=ssl_certificate_validation,
                                                cert=None, timeout=120, use_proxy=opt_use_proxy)
            helper.log_debug("response status_code:={}".format(response.status_code))

            # No http exception, but http post was not successful
            if response.status_code not in (200, 201, 204):
                helper.log_error(
                    'JIRA Service Desk ticket creation has failed!. url={}, data={}, HTTP Error={}, '
                    'content={}'.format(jira_url, data, response.status_code, response.text))

                record_url = 'https://localhost:' + str(splunkd_port) \
                             + '/servicesNS/nobody/' \
                               'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay'
                record_uuid = str(uuid.uuid1())
                helper.log_error('JIRA Service Desk failed ticket stored for next chance replay purposes in the '
                                 'replay KVstore with uuid: ' + record_uuid)
                headers = {
                    'Authorization': 'Splunk %s' % session_key,
                    'Content-Type': 'application/json'}

                record = '{"_key": "' + record_uuid + '", "ctime": "' + str(time.time()) \
                         + '", "status": "temporary_failure", "no_attempts": "1", "data": "' + checkstr(data) + '"}'
                response = requests.post(record_url, headers=headers, data=record,
                                         verify=False)
                if response.status_code not in (200, 201, 204):
                    helper.log_error(
                        'KVstore saving has failed!. url={}, data={}, HTTP Error={}, '
                        'content={}'.format(record_url, record, response.status_code, response.text))

                return 0

        # any exception such as proxy error, dns failure etc. will be catch here
        except Exception as e:
            helper.log_error("JIRA Service Desk ticket creation has failed!:{}".format(str(e)))
            helper.log_error(
                'message content={}'.format(data))

            # Store the failed publication in the replay KVstore
            record_url = 'https://localhost:' + str(
                splunkd_port) + '/servicesNS/nobody/' \
                                'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay'
            record_uuid = str(uuid.uuid1())
            helper.log_error('JIRA Service Desk failed ticket stored for next chance replay purposes in the '
                             'replay KVstore with uuid: ' + record_uuid)
            headers = {
                'Authorization': 'Splunk %s' % session_key,
                'Content-Type': 'application/json'}

            record = '{"_key": "' + record_uuid + '", "ctime": "' + str(time.time()) \
                     + '", "status": "temporary_failure", "no_attempts": "1", "data": "' + checkstr(data) + '"}'
            response = requests.post(record_url, headers=headers, data=record,
                                     verify=False)
            if response.status_code not in (200, 201, 204):
                helper.log_error(
                    'KVstore saving has failed!. url={}, data={}, HTTP Error={}, '
                    'content={}'.format(record_url, record, response.status_code, response.text))

            return 0

        else:
            helper.log_info('JIRA Service Desk ticket successfully created. {},'
                            ' content={}'.format(jira_url, response.text))
            return response.text
