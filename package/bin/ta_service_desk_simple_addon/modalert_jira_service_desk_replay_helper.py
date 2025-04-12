# encoding = utf-8

from requests.api import head


def process_event(helper, *args, **kwargs):

    # REPLAY START
    helper.set_log_level(helper.log_level)
    helper.log_info("Alert action jira_service_desk_replay started.")

    # Get the JIRA account
    account = helper.get_param("account")

    # Retrieve the session_key
    helper.log_debug("Get session_key.")
    session_key = helper.session_key

    # configuration manager
    import solnlib

    app = "TA-jira-service-desk-simple-addon"
    account_cfm = solnlib.conf_manager.ConfManager(
        session_key,
        app,
        realm=f"__REST_CREDENTIAL__#{app}#configs/conf-ta_service_desk_simple_addon_account",
    )
    splunk_ta_account_conf = account_cfm.get_conf(
        "ta_service_desk_simple_addon_account"
    ).get_all()

    # account details
    account_details = splunk_ta_account_conf[account]

    # Get authentication type
    auth_type = account_details.get("auth_type", 0)
    helper.log_debug(f"auth_type={auth_type}")

    # Get username
    username = account_details.get("username", 0)
    helper.log_debug(f"username={username}")
    # by convention
    jira_username = username

    # Get passowrd
    password = account_details.get("password", 0)
    # helper.log_info(f"password={password}")
    # by convention
    jira_password = password

    # Get authentication mode
    jira_auth_mode = account_details.get("jira_auth_mode", 0)
    helper.log_debug(f"jira_auth_mode={jira_auth_mode}")

    # Get jira_url
    jira_url = account_details.get("jira_url", 0)
    helper.log_debug(f"jira_url={jira_url}")

    # Get jira_ssl_certificate_validation
    jira_ssl_certificate_validation = int(
        account_details.get("jira_ssl_certificate_validation", 0)
    )
    helper.log_debug(
        f"jira_ssl_certificate_validation={jira_ssl_certificate_validation}"
    )
    ssl_certificate_validation = True
    if jira_ssl_certificate_validation == 0:
        ssl_certificate_validation = False
    helper.log_debug(f"ssl_certificate_validation={ssl_certificate_validation}")

    # Get jira_ssl_certificate_path
    # SSL certificate path - customers using an internal PKI can use this option to verify the certificate bundle
    # See: https://docs.python-requests.org/en/stable/user/advanced/#ssl-cert-verification
    # If it is set, and the SSL verification is enabled, and the file exists, the file path replaces the boolean in the requests calls
    jira_ssl_certificate_path = account_details.get("jira_ssl_certificate_path", 0)
    helper.log_debug(f"jira_ssl_certificate_path={jira_ssl_certificate_path}")
    if jira_ssl_certificate_path not in ["", "None", None]:
        helper.log_debug(f"jira_ssl_certificate_path={jira_ssl_certificate_path}")
        # replace the ssl_certificate_validation boolean by the SSL certiticate path if the file exists
        import os

        if ssl_certificate_validation and jira_ssl_certificate_path:
            if os.path.isfile(jira_ssl_certificate_path):
                ssl_certificate_validation = str(jira_ssl_certificate_path)

    # call the query URL REST Endpoint and pass the url and API token
    content = query_url(
        helper,
        account,
        jira_auth_mode,
        jira_url,
        jira_username,
        jira_password,
        ssl_certificate_validation,
    )

    return 0


def get_bearer_token(helper, session_key, **kwargs):

    import splunk
    import splunk.entity
    import splunklib.client as client
    import re

    # Get splunkd port
    entity = splunk.entity.getEntity(
        "/server",
        "settings",
        namespace="TA-jira-service-desk-simple-addon",
        sessionKey=session_key,
        owner="-",
    )
    splunkd_port = entity["mgmtHostPort"]

    service = client.connect(
        owner="nobody",
        app="TA-jira-service-desk-simple-addon",
        port=splunkd_port,
        token=session_key,
    )

    # Cred store
    storage_passwords = service.storage_passwords

    # The bearer token is stored in the credential store
    # However, likely due to the number of chars, the credential.content.get SDK command is unable to return its value in a single operation
    # As a workaround, we concatenate the different values return to form a complete object, finally we use a regex approach to extract its clear text value
    credential_realm = "__REST_CREDENTIAL__#TA-jira-service-desk-simple-addon#configs/conf-ta_service_desk_simple_addon_settings"
    bearer_token_rawvalue = ""

    for credential in storage_passwords:
        if credential.content.get("realm") == str(credential_realm):
            bearer_token_rawvalue = (
                f"{bearer_token_rawvalue}{str(credential.content.clear_password)}"
            )

    # extract a clean json object
    bearer_token_rawvalue_match = re.search(
        '\{"bearer_token":\s*"(.*)"\}', bearer_token_rawvalue
    )
    if bearer_token_rawvalue_match:
        bearer_token = bearer_token_rawvalue_match.group(1)

    return bearer_token


def query_url(
    helper,
    account,
    jira_auth_mode,
    jira_url,
    jira_username,
    jira_password,
    ssl_certificate_validation,
):

    import requests
    import json
    import time
    import base64

    import splunk.entity
    import splunk.Intersplunk

    # Retrieve the session_key
    helper.log_debug("Get session_key.")
    session_key = helper.session_key

    # Get splunkd port
    entity = splunk.entity.getEntity(
        "/server",
        "settings",
        namespace="TA-jira-service-desk-simple-addon",
        sessionKey=session_key,
        owner="-",
    )
    mydict = entity
    splunkd_port = mydict["mgmtHostPort"]
    helper.log_debug(f"splunkd_port={splunkd_port}")

    # For Splunk Cloud vetting, the URL must start with https://
    if not jira_url.startswith("https://"):
        jira_url = f"https://{jira_url}/rest/api/latest/issue"
    else:
        jira_url = f"{jira_url}/rest/api/latest/issue"

    # get proxy configuration
    proxy_config = helper.get_proxy()
    proxy_url = proxy_config.get("proxy_url")
    helper.log_debug(f"proxy_url={proxy_url}")

    if proxy_url is not None:
        opt_use_proxy = True
        helper.log_debug("use_proxy set to True")
    else:
        opt_use_proxy = False
        helper.log_debug("use_proxy set to False")

    # Retrieve parameters
    ticket_uuid = helper.get_param("ticket_uuid")
    helper.log_debug(f"ticket_uuid={ticket_uuid}")

    ticket_data = helper.get_param("ticket_data")
    helper.log_debug(f"ticket_data={ticket_data}")

    ticket_status = helper.get_param("ticket_status")
    helper.log_debug(f"ticket_status={ticket_status}")

    ticket_no_attempts = helper.get_param("ticket_no_attempts")
    helper.log_debug(f"ticket_no_attempts={ticket_no_attempts}")

    ticket_max_attempts = helper.get_param("ticket_max_attempts")
    helper.log_debug(f"ticket_max_attempts={ticket_max_attempts}")

    ticket_ctime = helper.get_param("ticket_ctime")
    helper.log_debug(f"ticket_ctime={ticket_ctime}")

    ticket_mtime = helper.get_param("ticket_mtime")
    helper.log_debug(f"ticket_mtime={ticket_mtime}")

    # Properly load json
    try:
        ticket_data = json.dumps(json.loads(ticket_data, strict=False), indent=4)
    except Exception as e:
        helper.log_error(
            f"json loads failed to accept some of the characters, raw json data before json.loads:={ticket_data}"
        )
        raise e

    # log json in debug mode
    helper.log_debug(f"json data for final rest call:={ticket_data}")

    # Build the authentication header for JIRA
    if str(jira_auth_mode) == "basic":
        authorization = f"{jira_username}:{jira_password}"
        b64_auth = base64.b64encode(authorization.encode()).decode()
        jira_headers = {
            "Authorization": f"Basic {b64_auth}",
            "Content-Type": "application/json",
        }
        # required when uploading attachments
        jira_headers_attachment = {
            "Authorization": f"Basic {b64_auth}",
            "X-Atlassian-Token": "no-check",
        }
    elif str(jira_auth_mode) == "pat":
        jira_headers = {
            "Authorization": f"Bearer {str(jira_password)}",
            "Content-Type": "application/json",
        }
        # required when uploading attachments
        jira_headers_attachment = {
            "Authorization": f"Bearer {str(jira_password)}",
            "X-Atlassian-Token": "no-check",
        }

    helper.log_debug(f"ticket_no_attempts={ticket_no_attempts}")
    helper.log_debug(f"ticket_max_attempts={ticket_max_attempts}")
    helper.log_debug(f"ticket_status={ticket_status}")

    # Handle distributed setup

    kvstore_instance = helper.get_global_setting("kvstore_instance")
    helper.log_debug(f"kvstore_instance={kvstore_instance}")

    # Get the bearer_token if required (store in the credential store)
    if kvstore_instance and str(kvstore_instance) != "null":
        bearer_token = get_bearer_token(helper, session_key)
        # helper.log_debug(f"bearer_token={bearer_token}")
    else:
        bearer_token = "null"

    if (kvstore_instance and str(kvstore_instance) != "null") and (
        bearer_token and bearer_token != "null"
    ):
        if not kvstore_instance.startswith("https://"):
            kvstore_instance = f"https://{str(kvstore_instance)}"
        splunk_headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
        }
    else:
        kvstore_instance = f"https://localhost:{str(splunkd_port)}"
        splunk_headers = {
            "Authorization": f"Splunk {session_key}",
            "Content-Type": "application/json",
        }

    # START

    # There is no need to verify for the connectivity to the KVstore instance, even if remote
    # Indeed, if we cannot access, there will be no content submitted to this handler

    if str(ticket_status) in "tagged_for_removal":

        helper.log_info(
            f"Ticket in KVstore with uuid={ticket_uuid} has reached the maximal number of attempts and is tagged for removal, purging the record from the KVstore:={ticket_data}"
        )

        # The JIRA ticket has been successfully created, and be safety removed from the KVstore
        record_url = f"{str(kvstore_instance)}/servicesNS/nobody/TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay/{ticket_uuid}"

        response = requests.delete(record_url, headers=splunk_headers, verify=False)
        if response.status_code not in (200, 201, 204):
            helper.log_error(
                f"KVstore delete operation has failed!. url={record_url}, HTTP Error={response.status_code}, content={response.text}"
            )
            return response.status_code
        else:
            return 0

    elif int(ticket_no_attempts) < int(ticket_max_attempts):

        helper.log_info(
            f"JIRA ticket creation attempting for record with uuid={ticket_uuid}"
        )

        # Try http post, catch exceptions and incorrect http return codes
        try:

            response = helper.send_http_request(
                jira_url,
                "POST",
                parameters=None,
                payload=ticket_data,
                headers=jira_headers,
                cookies=None,
                verify=ssl_certificate_validation,
                cert=None,
                timeout=120,
                use_proxy=opt_use_proxy,
            )
            helper.log_debug(f"response status_code:={response.status_code}")

            # No http exception, but http post was not successful
            if response.status_code not in (200, 201, 204):
                helper.log_error(
                    f"JIRA Service Desk ticket creation has failed!. url={jira_url}, ticket_data={ticket_data}, HTTP Error={response.status_code}, content={response.text}"
                )

                helper.log_info(f"Updating KVstore JIRA record with uuid={ticket_uuid}")

                record_url = f"{str(kvstore_instance)}/servicesNS/nobody/TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay/{ticket_uuid}"
                ticket_no_attempts = int(ticket_no_attempts) + 1

                # Update the KVstore record with the increment, and the new mtime
                record = {
                    "account": str(account),
                    "_key": str(ticket_uuid),
                    "ctime": str(ticket_ctime),
                    "mtime": str(time.time()),
                    "status": "temporary_failure",
                    "no_attempts": str(ticket_no_attempts),
                    "data": ticket_data,
                }

                response = requests.post(
                    record_url,
                    headers=splunk_headers,
                    data=json.dumps(record),
                    verify=False,
                )
                if response.status_code not in (200, 201, 204):
                    helper.log_error(
                        f"KVstore saving has failed!. url={record_url}, data={record}, HTTP Error={response.status_code}, content={response.text}"
                    )
                    return response.status_code

            else:
                # http post was successful
                ticket_creation_response = response.text
                helper.log_info(
                    f"JIRA Service Desk ticket successfully created. {jira_url}, content={ticket_creation_response}"
                )
                helper.log_info(f"Purging ticket in KVstore with uuid={ticket_uuid}")

                # The JIRA ticket has been successfully created, and be safety removed from the KVstore
                record_url = f"{str(kvstore_instance)}/servicesNS/nobody/TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay/{ticket_uuid}"

                response = requests.delete(
                    record_url, headers=splunk_headers, verify=False
                )
                if response.status_code not in (200, 201, 204):
                    helper.log_error(
                        f"KVstore delete operation has failed!. url={record_url}, HTTP Error={response.status_code}, content={response.text}"
                    )
                    return response.status_code
                else:
                    return ticket_creation_response

        # any exception such as proxy error, dns failure etc. will be catch here
        except Exception as e:

            helper.log_error(
                f"JIRA Service Desk ticket creation has failed! exception:{str(e)}, ticket_data:{ticket_data}"
            )

            helper.log_info(f"Updating KVstore JIRA record with uuid={ticket_uuid}")
            record_url = f"{str(kvstore_instance)}/servicesNS/nobody/TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay/{ticket_uuid}"
            ticket_no_attempts = int(ticket_no_attempts) + 1

            # Update the KVstore record with the increment, and the new mtime
            record = {
                "account": str(account),
                "_key": str(ticket_uuid),
                "ctime": str(ticket_ctime),
                "mtime": str(time.time()),
                "status": "temporary_failure",
                "no_attempts": str(ticket_no_attempts),
                "data": ticket_data,
            }

            response = requests.post(
                record_url,
                headers=splunk_headers,
                data=json.dumps(record),
                verify=False,
            )
            if response.status_code not in (200, 201, 204):
                helper.log_error(
                    f"KVstore saving has failed!. url={record_url}, data={record}, HTTP Error={response.status_code}, content={response.text}"
                )
                return response.status_code

    elif (int(ticket_no_attempts) >= int(ticket_max_attempts)) and str(
        ticket_status
    ) in "temporary_failure":

        helper.log_info(
            f"KVstore JIRA record with uuid={ticket_uuid} permanent failure!:={ticket_data}"
        )

        record_url = f"{str(kvstore_instance)}/servicesNS/nobody/TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay/{ticket_uuid}"

        # Update the KVstore record with the increment, and the new mtime
        record = {
            "account": str(account),
            "_key": str(ticket_uuid),
            "ctime": str(ticket_ctime),
            "mtime": str(time.time()),
            "status": "permanent_failure",
            "no_attempts": str(ticket_no_attempts),
            "data": ticket_data,
        }

        response = requests.post(
            record_url, headers=splunk_headers, data=json.dumps(record), verify=False
        )
        if response.status_code not in (200, 201, 204):
            helper.log_error(
                f"KVstore saving has failed!. url={record_url}, data={record}, HTTP Error={response.status_code}, content={response.text}"
            )
            return response.status_code
        else:
            return 0

    else:

        if str(ticket_status) in "permanent_failure":
            helper.log_info(
                f"Ticket in KVstore with uuid={ticket_uuid} will be tagged for removal and purged upon expiration."
            )
        else:
            helper.log_info(
                f"Ticket in KVstore with uuid={ticket_uuid} has no action detected ?"
            )
        return 0
