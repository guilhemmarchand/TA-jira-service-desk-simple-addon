# encoding = utf-8

def process_event(helper, *args, **kwargs):

    #REPLAY START    
    helper.set_log_level(helper.log_level)
    helper.log_info("Alert action jira_service_desk_replay started.")

    # Get the JIRA account
    account = helper.get_param("account")
    helper.log_info("account={}".format(account))

    # Retrieve the session_key
    helper.log_debug("Get session_key.")
    session_key = helper.session_key

    # configuration manager
    import solnlib
    app = 'TA-jira-service-desk-simple-addon'
    account_cfm = solnlib.conf_manager.ConfManager(
        session_key,
        app,
        realm="__REST_CREDENTIAL__#{}#configs/conf-ta_service_desk_simple_addon_account".format(app))
    splunk_ta_account_conf = account_cfm.get_conf("ta_service_desk_simple_addon_account").get_all()
    helper.log_info("account={}".format(splunk_ta_account_conf))

    # account details
    account_details = splunk_ta_account_conf[account]

    # Get authentication type
    auth_type = account_details.get("auth_type", 0)
    helper.log_info("auth_type={}".format(auth_type))

    # Get username
    username = account_details.get("username", 0)
    helper.log_info("username={}".format(username))
    # by convention
    jira_username = username

    # Get passowrd
    password = account_details.get("password", 0)
    # helper.log_info("password={}".format(password))
    # by convention
    jira_password = password

    # Get jira_url
    jira_url = account_details.get("jira_url", 0)
    helper.log_info("jira_url={}".format(jira_url))

    # Get jira_ssl_certificate_validation
    jira_ssl_certificate_validation = int(account_details.get("jira_ssl_certificate_validation", 0))
    helper.log_info("jira_ssl_certificate_validation={}".format(jira_ssl_certificate_validation))
    ssl_certificate_validation = True
    if jira_ssl_certificate_validation == 0:
        ssl_certificate_validation = False
    helper.log_debug("ssl_certificate_validation={}".format(ssl_certificate_validation))

    # Get jira_ssl_certificate_path
    # SSL certificate path - customers using an internal PKI can use this option to verify the certificate bundle
    # See: https://docs.python-requests.org/en/stable/user/advanced/#ssl-cert-verification
    # If it is set, and the SSL verification is enabled, and the file exists, the file path replaces the boolean in the requests calls    
    jira_ssl_certificate_path = account_details.get("jira_ssl_certificate_path", 0)
    helper.log_info("jira_ssl_certificate_path={}".format(jira_ssl_certificate_path))
    if jira_ssl_certificate_path not in ["", "None", None]:
        helper.log_debug("jira_ssl_certificate_path={}".format(jira_ssl_certificate_path))
        # replace the ssl_certificate_validation boolean by the SSL certiticate path if the file exists
        import os
        if ssl_certificate_validation and jira_ssl_certificate_path:
            if os.path.isfile(jira_ssl_certificate_path):
                ssl_certificate_validation = str(jira_ssl_certificate_path)

    #call the query URL REST Endpoint and pass the url and API token
    content = query_url(helper, jira_url, jira_username, jira_password, ssl_certificate_validation)  

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
    entity = splunk.entity.getEntity('/server', 'settings', namespace='TA-jira-service-desk-simple-addon',
                                     sessionKey=session_key, owner='-')
    mydict = entity
    splunkd_port = mydict['mgmtHostPort']
    helper.log_debug("splunkd_port={}".format(splunkd_port))

    # For Splunk Cloud vetting, the URL must start with https://
    if not jira_url.startswith("https://"):
        jira_url = 'https://' + jira_url + '/rest/api/latest/issue'
    else:
        jira_url = jira_url + '/rest/api/latest/issue'

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

        # Try http post, catch exceptions and incorrect http return codes
        try:

            response = helper.send_http_request(jira_url, "POST", parameters=None, payload=ticket_data,
                                                headers=headers, cookies=None, verify=ssl_certificate_validation,
                                                cert=None, timeout=120, use_proxy=opt_use_proxy)
            helper.log_debug("response status_code:={}".format(response.status_code))

            # No http exception, but http post was not successful
            if response.status_code not in (200, 201, 204):
                helper.log_error(
                    'JIRA Service Desk ticket creation has failed!. url={}, ticket_data={}, HTTP Error={}, '
                    'content={}'.format(jira_url, ticket_data, response.status_code, response.text))

                helper.log_info('Updating KVstore JIRA record with uuid=' + ticket_uuid)

                record_url = 'https://localhost:' + str(
                    splunkd_port) + '/servicesNS/nobody/' \
                                    'TA-jira-service-desk-simple-addon/storage/collections/data/' \
                                    'kv_jira_failures_replay/' + ticket_uuid
                headers = {
                    'Authorization': 'Splunk %s' % session_key,
                    'Content-Type': 'application/json'}
                ticket_no_attempts = int(ticket_no_attempts) + 1

                # Update the KVstore record with the increment, and the new mtime
                record = '{"_key": "' + str(ticket_uuid) + '", "ctime": "' + str(ticket_ctime) \
                         + '", "mtime": "' + str(time.time()) \
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
                # http post was successful
                ticket_creation_response = response.text
                helper.log_info('JIRA Service Desk ticket successfully created. {}, '
                                'content={}'.format(jira_url, ticket_creation_response))
                helper.log_info("Purging ticket in KVstore with uuid=" + ticket_uuid)

                # The JIRA ticket has been successfully created, and be safety removed from the KVstore
                record_url = 'https://localhost:' + str(
                    splunkd_port) + '/servicesNS/nobody/' \
                                    'TA-jira-service-desk-simple-addon/storage/collections/data/' \
                                    'kv_jira_failures_replay/' + ticket_uuid
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

        # any exception such as proxy error, dns failure etc. will be catch here
        except Exception as e:

            helper.log_error('JIRA Service Desk ticket creation has failed! exception:{},'
                             ' ticket_data:{}'.format(str(e), ticket_data))

            helper.log_info('Updating KVstore JIRA record with uuid=' + ticket_uuid)
            record_url = 'https://localhost:' + str(
                splunkd_port) + '/servicesNS/nobody/' \
                                'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay/' \
                         + ticket_uuid
            headers = {
                'Authorization': 'Splunk %s' % session_key,
                'Content-Type': 'application/json'}
            ticket_no_attempts = int(ticket_no_attempts) + 1

            # Update the KVstore record with the increment, and the new mtime
            record = '{"_key": "' + str(ticket_uuid) + '", "ctime": "' + str(ticket_ctime) + '", "mtime": "' + str(
                time.time()) \
                     + '", "status": "temporary_failure", "no_attempts": "' + str(ticket_no_attempts) \
                     + '", "data": "' + checkstr(ticket_data) + '"}'
            response = requests.post(record_url, headers=headers, data=record,
                                     verify=False)
            if response.status_code not in (200, 201, 204):
                helper.log_error(
                    'KVstore saving has failed!. url={}, data={}, HTTP Error={}, '
                    'content={}'.format(record_url, record, response.status_code, response.text))
                return response.status_code

    elif (int(ticket_no_attempts) >= int(ticket_max_attempts)) and str(ticket_status) in "temporary_failure":

        helper.log_info('KVstore JIRA record with uuid=' + ticket_uuid
                        + " permanent failure!:={}".format(ticket_data))

        record_url = 'https://localhost:' + str(
            splunkd_port) + '/servicesNS/nobody/' \
                            'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay/' \
                     + ticket_uuid
        headers = {
            'Authorization': 'Splunk %s' % session_key,
            'Content-Type': 'application/json'}

        # Update the KVstore record with the increment, and the new mtime
        record = '{"_key": "' + str(ticket_uuid) + '", "ctime": "' + str(ticket_ctime) + '", "mtime": "' \
                 + str(time.time()) \
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
            splunkd_port) + '/servicesNS/nobody/' \
                            'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay/' \
                     + ticket_uuid
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
