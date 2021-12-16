# encoding = utf-8

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example gets the alert action parameters and prints them to the log
    account = helper.get_param("account")
    helper.log_info("account={}".format(account))

    kvstore_target = helper.get_param("kvstore_target")
    helper.log_info("kvstore_target={}".format(kvstore_target))

    record_key = helper.get_param("record_key")
    helper.log_info("record_key={}".format(record_key))


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

    helper.log_info("Alert action jira_service_desk_test started.")

    import requests
    import json
    import uuid
    import time
    import base64
    import hashlib

    import splunk.entity
    import splunk.Intersplunk
    import splunklib.client as client

    # Retrieve the session_key
    helper.log_info("Get session_key.")
    session_key = helper.session_key

    # Get account
    account = helper.get_param("account")

    # configuration manager
    import solnlib
    app = 'TA-jira-service-desk-simple-addon'
    account_cfm = solnlib.conf_manager.ConfManager(
        session_key,
        app,
        realm="__REST_CREDENTIAL__#{}#configs/conf-ta_service_desk_simple_addon_account".format(app))
    splunk_ta_account_conf = account_cfm.get_conf("ta_service_desk_simple_addon_account").get_all()

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

    # Get authentication mode
    jira_auth_mode = account_details.get("jira_auth_mode", 0)
    helper.log_info("jira_auth_mode={}".format(jira_auth_mode))

    # Get jira_url
    jira_url = account_details.get("jira_url", 0)
    helper.log_info("jira_url={}".format(jira_url))

    # Get jira_ssl_certificate_validation
    jira_ssl_certificate_validation = int(account_details.get("jira_ssl_certificate_validation", 0))
    helper.log_info("jira_ssl_certificate_validation={}".format(jira_ssl_certificate_validation))
    ssl_certificate_validation = True
    if jira_ssl_certificate_validation == 0:
        ssl_certificate_validation = False
    helper.log_info("ssl_certificate_validation={}".format(ssl_certificate_validation))

    # Get jira_ssl_certificate_path
    # SSL certificate path - customers using an internal PKI can use this option to verify the certificate bundle
    # See: https://docs.python-requests.org/en/stable/user/advanced/#ssl-cert-verification
    # If it is set, and the SSL verification is enabled, and the file exists, the file path replaces the boolean in the requests calls    
    jira_ssl_certificate_path = account_details.get("jira_ssl_certificate_path", 0)
    helper.log_info("jira_ssl_certificate_path={}".format(jira_ssl_certificate_path))
    if jira_ssl_certificate_path not in ["", "None", None]:
        helper.log_info("jira_ssl_certificate_path={}".format(jira_ssl_certificate_path))
        # replace the ssl_certificate_validation boolean by the SSL certiticate path if the file exists
        import os
        if ssl_certificate_validation and jira_ssl_certificate_path:
            if os.path.isfile(jira_ssl_certificate_path):
                ssl_certificate_validation = str(jira_ssl_certificate_path)

    # Get splunkd port
    entity = splunk.entity.getEntity('/server', 'settings',
                                     namespace='TA-jira-service-desk-simple-addon', sessionKey=session_key, owner='-')
    mydict = entity
    splunkd_port = mydict['mgmtHostPort']
    helper.log_info("splunkd_port={}".format(splunkd_port))

    service = client.connect(
        owner="nobody",
        app="TA-jira-service-desk-simple-addon",
        port=splunkd_port,
        token=session_key
    )
    storage_passwords = service.storage_passwords

    # Get authentication mode
    jira_auth_mode = account_details.get("jira_auth_mode", 0)
    helper.log_info("jira_auth_mode={}".format(jira_auth_mode))

    # For Splunk Cloud vetting, the URL must start with https://
    if not jira_url.startswith("https://"):
        jira_url = 'https://' + jira_url

    # get proxy configuration
    # note: the proxy dict is used with requests calls when attachment is enabled
    proxy_config = helper.get_proxy()
    proxy_enabled = "0"
    proxy_url = proxy_config.get("proxy_url")
    proxy_dict = None
    proxy_username = None
    helper.log_info("proxy_url={}".format(proxy_url))

    if proxy_url is not None:
        opt_use_proxy = True
        helper.log_info("use_proxy set to True")

        # to be used for attachment purposes with the requests module
        conf_file = "ta_service_desk_simple_addon_settings"
        confs = service.confs[str(conf_file)]
        for stanza in confs:
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

    else:
        opt_use_proxy = False
        helper.log_info("use_proxy set to False")

    # Build the authentication header for JIRA
    if str(jira_auth_mode) == 'basic':
        authorization = jira_username + ':' + jira_password
        b64_auth = base64.b64encode(authorization.encode()).decode()
        jira_headers = {
            'Authorization': 'Basic %s' % b64_auth,
            'Content-Type': 'application/json',
        }
    elif str(jira_auth_mode) == 'pat':
        jira_headers = {
            'Authorization': 'Bearer %s' % str(jira_password),
            'Content-Type': 'application/json',
        }

    ############
    # Main start
    ############

    # KVstore target
    test_kvstore_target = helper.get_param("test_kvstore_target")
    helper.log_info("test_kvstore_target={}".format(test_kvstore_target))

    # KVstore record to test
    test_record_key = helper.get_param("test_record_key")
    helper.log_info("test_record_key={}".format(test_record_key))

    # Loop within events and proceed
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

        # record test
        test_record_key = helper.get_param("test_record_key")
        helper.log_info("test_record_key={}".format(test_record_key))

        # data test
        test_data = helper.get_param("test_data")
        helper.log_info("test_data={}".format(test_data))

        # test based on the data field, convert the data to an md5 and check if that record exists in the KVstore collection
        if test_data and test_data != "null":

            # turn this into an md5
            test_md5sum = hashlib.md5(test_data.encode())
            test_md5sum = test_md5sum.hexdigest()
            helper.log_info("test_md5sum={}".format(test_md5sum))

            # Test verifying if the record exists in the backlog KVstore
            record_url = 'https://' + str(test_kvstore_target) + ':' + str(splunkd_port) \
                        + '/servicesNS/nobody/' \
                        'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_issues_backlog/' \
                        + str(test_md5sum)
            headers = {
                'Authorization': 'Splunk %s' % session_key,
                'Content-Type': 'application/json'}

            try:
                response = requests.get(record_url, headers=headers, verify=False)
                if response.status_code == 200:
                    helper.log_info("test data: record was found in the KVstore collection, request response status_code:={}".format(response.status_code))
                else:
                    helper.log_info("test data: assuming the record was not found in the KVstore collection as the endpoint did not return an HTTP 200, request response status_code:={}".format(response.status_code))

            except Exception as e:
                helper.log_error("requests to the KVstore has failed with exception={}".format(e))

        # test based on the record provided key
        if test_record_key and test_record_key != "null":

            # Test verifying if the record exists in the backlog KVstore
            record_url = 'https://' + str(test_kvstore_target) + ':' + str(splunkd_port) \
                        + '/servicesNS/nobody/' \
                        'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_issues_backlog/' \
                        + str(test_record_key)
            headers = {
                'Authorization': 'Splunk %s' % session_key,
                'Content-Type': 'application/json'}
            try:
                response = requests.get(record_url, headers=headers, verify=False)
                if response.status_code == 200:
                    helper.log_info("test record key: record was found in the KVstore collection, request response status_code:={}".format(response.status_code))
                else:
                    helper.log_info("test record key: assuming the record was not found in the KVstore collection as the endpoint did not return an HTTP 200, request response status_code:={}".format(response.status_code))
            except Exception as e:
                helper.log_error("requests to the KVstore has failed with exception={}".format(e))

        # test connectivity to JIRA
        test_endpoint = str(jira_url) + "/rest/api/2/myself"
        try:
            response = helper.send_http_request(test_endpoint, "GET", parameters=None,
                                                headers=jira_headers, cookies=None,
                                                verify=ssl_certificate_validation,
                                                cert=None, timeout=120, use_proxy=opt_use_proxy)
            helper.log_info("response status_code:={}".format(response.status_code))

            # No http exception, but http post was not successful
            if response.status_code not in (200, 201, 204):
                helper.log_error(
                    'test JIRA connectivity: failure url={}, HTTP Error={}, '
                    'content={}'.format(test_endpoint, response.status_code, response.text))
            else:
                helper.log_info("test JIRA connectivity: success, request response status_code:={}, content:={}".format(response.status_code, json.loads(response.text)))

        except Exception as e:
            helper.log_error("requests to JIRA has failed with exception={}".format(e))

    return 0
