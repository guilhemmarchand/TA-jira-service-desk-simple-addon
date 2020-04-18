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
    helper.log_info("Alert action jira_service_desk_replay started.")

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

    return 0


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
    entity = splunk.entity.getEntity('/server', 'settings', namespace='TA-jira-service-desk-simple-addon', sessionKey=session_key, owner='-')
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

    # Retrieve parameters
    ticket_uuid = helper.get_param("ticket_uuid")
    helper.log_debug("ticket_uuid={}".format(ticket_uuid))

    ticket_data = helper.get_param("ticket_data")
    helper.log_debug("ticket_data={}".format(ticket_data))
    #ticket_data = checkstr(ticket_data)

    ticket_status = helper.get_param("ticket_status")
    helper.log_debug("ticket_status={}".format(ticket_status))

    ticket_no_attempts = helper.get_param("ticket_no_attempts")
    helper.log_debug("ticket_no_attempts={}".format(ticket_no_attempts))

    ticket_max_attempts = helper.get_param("ticket_max_attempts")
    helper.log_debug("ticket_max_attempts={}".format(ticket_max_attempts))

    ticket_ctime = helper.get_param("ticket_ctime")
    helper.log_debug("ticket_ctime={}".format(ticket_ctime))

    ticket_mtime = helper.get_param("ticket_mtime")
    helper.log_debug("ticket_mtime={}".format(ticket_mtime))

    # Properly load json
    try:
        ticket_data = json.dumps(json.loads(ticket_data, strict=False), indent=4)
    except Exception as e:
        helper.log_error("json loads failed to accept some of the characters,"
                         " raw json data before json.loads:={}".format(ticket_data))
        raise e

    # log json in debug mode
    helper.log_debug("json data for final rest call:={}".format(ticket_data))

    # Build the header including basic auth
    authorization = jira_username + ':' + jira_password
    b64_auth = base64.b64encode(authorization.encode()).decode()
    headers = {
        'Authorization': 'Basic %s' % b64_auth,
        'Content-Type': 'application/json',
    }

    helper.log_debug("ticket_no_attempts={}".format(ticket_no_attempts))
    helper.log_debug("ticket_max_attempts={}".format(ticket_max_attempts))
    helper.log_debug("ticket_status={}".format(ticket_status))

    if int(ticket_no_attempts) < int(ticket_max_attempts):

        helper.log_info('JIRA ticket creation attempting for record with uuid=' + ticket_uuid)

        response = helper.send_http_request(jira_url, "POST", parameters=None, payload=ticket_data,
                                            headers=headers, cookies=None, verify=ssl_certificate_validation,
                                            cert=None, timeout=None, use_proxy=opt_use_proxy)

        if response.status_code not in (200, 201, 204):
            helper.log_error(
                'JIRA Service Desk ticket creation has failed!. url={}, ticket_data={}, HTTP Error={}, '
                'content={}'.format(jira_url, ticket_data, response.status_code, response.text))

            helper.log_info('Updating KVstore JIRA record with uuid=' + ticket_uuid)

            record_url = 'https://localhost:' + str(
                splunkd_port) + '/servicesNS/nobody/TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay/' + ticket_uuid
            headers = {
                'Authorization': 'Splunk %s' % session_key,
                'Content-Type': 'application/json'}
            ticket_no_attempts = int(ticket_no_attempts) + 1

            # Update the KVstore record with the increment, and the new mtime
            record = '{"_key": "' + str(ticket_uuid) + '", "ctime": "' + str(ticket_ctime) + '", "mtime": "' + str(time.time()) \
                     + '", "status": "temporary_failure", "no_attempts": "' + str(ticket_no_attempts) \
                     + '", "data": "' + checkstr(ticket_data) + '"}'
            response = requests.post(record_url, headers=headers, data=record,
                                     verify=False)
            if response.status_code not in (200, 201, 204):
                helper.log_error(
                    'KVstore saving has failed!. url={}, data={}, HTTP Error={}, '
                    'content={}'.format(record_url, record, response.status_code, response.text))
                return response.status_code

        else:
            ticket_creation_response = response.text
            helper.log_info('JIRA Service Desk ticket successfully created. {}, content={}'.format(jira_url,
                                                                                                   ticket_creation_response))
            helper.log_info("Purging ticket in KVstore with uuid=" + ticket_uuid)

            # The JIRA ticket has been successfully created, and be safety removed from the KVstore
            record_url = 'https://localhost:' + str(
                splunkd_port) + '/servicesNS/nobody/TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay/' + ticket_uuid
            headers = {
                'Authorization': 'Splunk %s' % session_key,
                'Content-Type': 'application/json'}

            response = requests.delete(record_url, headers=headers, verify=False)
            if response.status_code not in (200, 201, 204):
                helper.log_error(
                    'KVstore delete operation has failed!. url={}, HTTP Error={}, '
                    'content={}'.format(record_url, response.status_code, response.text))
                return response.status_code
            else:
                return ticket_creation_response

    elif (int(ticket_no_attempts) >= int(ticket_max_attempts)) and str(ticket_status) in "temporary_failure":

        helper.log_info('KVstore JIRA record with uuid=' + ticket_uuid
                        + " permanent failure!:={}".format(ticket_data))

        record_url = 'https://localhost:' + str(
            splunkd_port) + '/servicesNS/nobody/TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay/' + ticket_uuid
        headers = {
            'Authorization': 'Splunk %s' % session_key,
            'Content-Type': 'application/json'}

        # Update the KVstore record with the increment, and the new mtime
        record = '{"_key": "' + str(ticket_uuid) + '", "ctime": "' + str(ticket_ctime) + '", "mtime": "' + str(time.time()) \
                 + '", "status": "permanent_failure", "no_attempts": "' + str(ticket_no_attempts) \
                 + '", "data": "' + checkstr(ticket_data) + '"}'
        response = requests.post(record_url, headers=headers, data=record,
                                 verify=False)
        if response.status_code not in (200, 201, 204):
            helper.log_error(
                'KVstore saving has failed!. url={}, data={}, HTTP Error={}, '
                'content={}'.format(record_url, record, response.status_code, response.text))
            return response.status_code
        else:
            return 0

    elif int(ticket_no_attempts) >= int(ticket_max_attempts) and str(ticket_status) in "tagged_for_removal":

        helper.log_info("Ticket in KVstore with uuid=" + ticket_uuid
                        + " has reached the maximal number of attempts and is tagged for removal,"
                          " purging the record from the KVstore:={}".format(ticket_data))

        # The JIRA ticket has been successfully created, and be safety removed from the KVstore
        record_url = 'https://localhost:' + str(
            splunkd_port) + '/servicesNS/nobody/TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay/' + ticket_uuid
        headers = {
            'Authorization': 'Splunk %s' % session_key,
            'Content-Type': 'application/json'}

        response = requests.delete(record_url, headers=headers, verify=False)
        if response.status_code not in (200, 201, 204):
            helper.log_error(
                'KVstore delete operation has failed!. url={}, HTTP Error={}, '
                'content={}'.format(record_url, response.status_code, response.text))
            return response.status_code
        else:
            return 0

    else:

        if str(ticket_status) in "permanent_failure":
            helper.log_info("Ticket in KVstore with uuid=" + ticket_uuid
                            + " will be tagged for removal and purged upon expiration.")
        else:
            helper.log_info("Ticket in KVstore with uuid=" + ticket_uuid
                            + " has no action detected ?")
        return 0
