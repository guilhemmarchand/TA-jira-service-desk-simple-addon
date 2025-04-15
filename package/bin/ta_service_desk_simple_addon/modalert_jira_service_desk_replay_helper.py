# encoding = utf-8

# Standard library imports
import json
import os
import sys
import time

# Third-party imports
import requests

splunkhome = os.environ["SPLUNK_HOME"]
sys.path.append(
    os.path.join(splunkhome, "etc", "apps", "TA-jira-service-desk-simple-addon", "lib")
)

# import least privileges access libs
from ta_jira_libs import (
    jira_get_conf,
    jira_get_accounts,
    jira_get_account,
    jira_test_connectivity,
    jira_build_headers,
    jira_handle_ssl_certificate,
    jira_get_bearer_token,
)


def process_event(helper, *args, **kwargs):

    # REPLAY START
    helper.set_log_level(helper.log_level)
    helper.log_info("Alert action jira_service_desk_replay started.")

    # Get the JIRA account
    account = helper.get_param("account")

    # Retrieve the session_key
    helper.log_debug("Get session_key.")
    session_key = helper.session_key

    # server_uri
    server_uri = helper.settings["server_uri"]

    # get all acounts
    accounts_dict = jira_get_accounts(session_key, server_uri)
    accounts = accounts_dict.get("accounts", [])

    # account configuration

    # Stop here if we cannot find the submitted account
    if not account in accounts:
        raise ValueError(
            f"The account={account} does not exist, check your inputs and configuration.",
        )

    # get account configuration
    account_conf = jira_get_account(
        session_key,
        server_uri,
        account,
    )

    jira_auth_mode = account_conf.get("auth_mode", "basic")
    jira_url = account_conf.get("jira_url", None)
    jira_ssl_certificate_path = account_conf.get("jira_ssl_certificate_path", None)
    jira_ssl_certificate_pem = account_conf.get("jira_ssl_certificate_pem", None)
    jira_username = account_conf.get("username", None)
    jira_password = account_conf.get("jira_password", None)
    # end of get configuration

    # Handle SSL certificate configuration
    ssl_config, temp_cert_file = jira_handle_ssl_certificate(
        jira_ssl_certificate_path, jira_ssl_certificate_pem
    )

    # test connectivity systematically but do not fail
    try:
        jira_test_connectivity(session_key, server_uri, account)
    except Exception as e:
        helper.log_error(
            f"Failed to test connectivity to Jira, account={account}, exception={str(e)}"
        )

    # call the query URL REST Endpoint and pass the url and API token
    content = query_url(
        helper,
        account,
        jira_auth_mode,
        jira_url,
        jira_username,
        jira_password,
        ssl_config,
    )

    # Clean up the temporary file if it was created
    if temp_cert_file:
        try:
            os.unlink(temp_cert_file.name)
        except:
            pass  # Ignore cleanup errors

    return 0


def query_url(
    helper,
    account,
    jira_auth_mode,
    jira_url,
    jira_username,
    jira_password,
    ssl_config,
):

    # Retrieve the session_key
    helper.log_debug("Get session_key.")
    session_key = helper.session_key

    # server_uri
    server_uri = helper.settings["server_uri"]

    # get conf
    jira_conf = jira_get_conf(session_key, server_uri)

    # set timeout
    timeout = int(jira_conf["advanced_configuration"].get("timeout", 120))

    # get proxy configuration
    proxy_conf = jira_conf["proxy"]
    proxy_dict = proxy_conf.get("proxy_dict", {})

    # For Splunk Cloud vetting, the URL must start with https://
    if not jira_url.startswith("https://"):
        jira_url = f"https://{jira_url}/rest/api/latest/issue"
    else:
        jira_url = f"{jira_url}/rest/api/latest/issue"

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
    jira_headers = jira_build_headers(jira_auth_mode, jira_username, jira_password)

    helper.log_debug(f"ticket_no_attempts={ticket_no_attempts}")
    helper.log_debug(f"ticket_max_attempts={ticket_max_attempts}")
    helper.log_debug(f"ticket_status={ticket_status}")

    # Handle distributed setup

    kvstore_instance = helper.get_global_setting("kvstore_instance")
    helper.log_debug(f"kvstore_instance={kvstore_instance}")

    # Get the bearer_token if required (store in the credential store)
    bearer_token = None
    if kvstore_instance and str(kvstore_instance) != "null":
        bearer_token = jira_get_bearer_token(session_key, server_uri)

    if (kvstore_instance and str(kvstore_instance) != "null") and bearer_token:
        if not kvstore_instance.startswith("https://"):
            kvstore_instance = f"https://{str(kvstore_instance)}"
        splunk_headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
        }
    else:
        kvstore_instance = server_uri
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

            response = requests.post(
                jira_url,
                data=ticket_data,
                headers=jira_headers,
                verify=ssl_config if ssl_config else True,
                proxies=proxy_dict,
                timeout=timeout,
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
