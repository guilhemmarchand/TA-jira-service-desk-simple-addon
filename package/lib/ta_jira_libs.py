#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import requests
import json
import logging
import base64
import urllib3
import tempfile
from requests.structures import CaseInsensitiveDict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

sys.path.append(
    os.path.join(splunkhome, "etc", "apps", "TA-jira-service-desk-simple-addon", "lib")
)


# get configuration
def jira_get_conf(session_key, splunkd_uri):
    """
    get system wide conf with least privilege approach
    """

    # Ensure splunkd_uri starts with "https://"
    if not splunkd_uri.startswith("https://"):
        splunkd_uri = f"https://{splunkd_uri}"

    # Build header and target URL
    headers = CaseInsensitiveDict()
    headers["Authorization"] = f"Splunk {session_key}"
    target_url = f"{splunkd_uri}/services/jira_service_desk/manager/get_conf"

    # Create a requests session for better performance
    session = requests.Session()
    session.headers.update(headers)

    try:
        # Use a context manager to handle the request
        with session.get(target_url, verify=False) as response:
            if response.ok:
                logging.debug(f'Success retrieving conf, data="{response.text}"')
                response_json = response.json()
                return response_json
            else:
                error_message = f'Failed to retrieve conf, status_code={response.status_code}, response_text="{response.text}"'
                logging.error(error_message)
                raise Exception(error_message)

    except Exception as e:
        error_message = f'Failed to retrieve conf, exception="{str(e)}"'
        logging.error(error_message)
        raise Exception(error_message)


# get accounts
def jira_get_accounts(session_key, splunkd_uri):
    """
    get list of configured accounts with least privilege approach
    """

    # Ensure splunkd_uri starts with "https://"
    if not splunkd_uri.startswith("https://"):
        splunkd_uri = f"https://{splunkd_uri}"

    # Build header and target URL
    headers = CaseInsensitiveDict()
    headers["Authorization"] = f"Splunk {session_key}"
    target_url = f"{splunkd_uri}/services/jira_service_desk/manager/list_accounts"

    # Create a requests session for better performance
    session = requests.Session()
    session.headers.update(headers)

    try:
        # Use a context manager to handle the request
        with session.get(target_url, verify=False) as response:
            if response.ok:
                logging.debug(f'Success retrieving accounts, data="{response.text}"')
                response_json = response.json()
                return response_json
            else:
                error_message = f'Failed to retrieve accounts, status_code={response.status_code}, response_text="{response.text}"'
                logging.error(error_message)
                raise Exception(error_message)

    except Exception as e:
        error_message = f'Failed to retrieve accounts, exception="{str(e)}"'
        logging.error(error_message)
        raise Exception(error_message)


# get account
def jira_get_account(session_key, splunkd_uri, account):
    """
    get account creds with least privilege approach
    """

    # Ensure splunkd_uri starts with "https://"
    if not splunkd_uri.startswith("https://"):
        splunkd_uri = f"https://{splunkd_uri}"

    # Build header and target URL
    headers = CaseInsensitiveDict()
    headers["Authorization"] = f"Splunk {session_key}"
    target_url = f"{splunkd_uri}/services/jira_service_desk/manager/get_account"

    # Create a requests session for better performance
    session = requests.Session()
    session.headers.update(headers)

    try:
        # Use a context manager to handle the request
        with session.post(
            target_url,
            data=json.dumps({"account": account}),
            verify=False,
        ) as response:
            if response.ok:
                logging.debug(f'Success retrieving account, data="{response.text}"')
                response_json = response.json()
                return response_json
            else:
                error_message = f'Failed to retrieve account, status_code={response.status_code}, response_text="{response.text}"'
                logging.error(error_message)
                raise Exception(error_message)

    except Exception as e:
        error_message = f'Failed to retrieve account, exception="{str(e)}"'
        logging.error(error_message)
        raise Exception(error_message)


# Test connectivity to Jira using our API endpoint
def jira_test_connectivity(session_key, splunkd_uri, account):
    """
    Test connectivity to a JIRA instance
    """
    temp_cert_file = None

    # Ensure splunkd_uri starts with "https://"
    if not splunkd_uri.startswith("https://"):
        splunkd_uri = f"https://{splunkd_uri}"

    # Build header and target URL
    headers = CaseInsensitiveDict()
    headers["Authorization"] = f"Splunk {session_key}"
    target_url = f"{splunkd_uri}/services/jira_service_desk/manager/test_connectivity"

    # Create a requests session for better performance
    session = requests.Session()
    session.headers.update(headers)

    try:
        # Use a context manager to handle the request
        with session.post(
            target_url,
            data=json.dumps({"account": account}),
            verify=False,  # local splunkd API
        ) as response:
            if response.ok:
                logging.debug(
                    f'Success testing connectivity to Jira, account="{account}", status_code={response.status_code}, data="{response.text}"'
                )
                response_json = response.json()
                return response_json
            else:
                error_message = f'Failed to test connectivity to Jira, account="{account}", status_code={response.status_code}, response_text="{response.text}"'
                logging.error(error_message)
                raise Exception(error_message)

    except Exception as e:
        error_message = f'Failed to test connectivity to Jira, account="{account}", exception="{str(e)}"'
        logging.error(error_message)
        raise Exception(error_message)


# Get bearer token using our API endpoint
def jira_get_bearer_token(session_key, splunkd_uri):

    # Ensure splunkd_uri starts with "https://"
    if not splunkd_uri.startswith("https://"):
        splunkd_uri = f"https://{splunkd_uri}"

    # Build header and target URL
    headers = CaseInsensitiveDict()
    headers["Authorization"] = f"Splunk {session_key}"
    target_url = f"{splunkd_uri}/services/jira_service_desk/manager/get_bearer_token"

    # Create a requests session for better performance
    session = requests.Session()
    session.headers.update(headers)

    try:
        # Use a context manager to handle the request
        with session.get(target_url, verify=False) as response:
            if response.ok:
                logging.debug(
                    f'Successfully retrieved bearer token, status_code={response.status_code}, data="{response.text}"'
                )
                response_json = response.json()
                bearer_token = response_json["bearer_token"]
                return bearer_token
            else:
                error_message = f'Failed to retrieve bearer token, status_code={response.status_code}, response_text="{response.text}"'
                logging.error(error_message)
                raise Exception(error_message)

    except Exception as e:
        error_message = f'Failed to retrieve bearer token, exception="{str(e)}"'
        logging.error(error_message)
        raise Exception(error_message)


# A simple function to build the jira headers
def jira_build_headers(jira_auth_mode, jira_username, jira_password):
    """
    Build JIRA headers based on authentication mode
    """
    # Build the authentication header for JIRA
    if str(jira_auth_mode) == "basic":
        authorization = f"{jira_username}:{jira_password}"
        b64_auth = base64.b64encode(authorization.encode()).decode()
        jira_headers = {
            "Authorization": f"Basic {b64_auth}",
            "Content-Type": "application/json",
        }
    elif str(jira_auth_mode) == "pat":
        jira_headers = {
            "Authorization": f"Bearer {str(jira_password)}",
            "Content-Type": "application/json",
        }
    else:
        raise Exception(f"Invalid authentication mode: {jira_auth_mode}")

    return jira_headers


# A simple function to build the ssl_config
def jira_build_ssl_config(
    jira_ssl_certificate_path, jira_ssl_certificate_pem=None, account_name=None
):
    """
    Build SSL configuration for JIRA connection.
    Supports both certificate path and PEM content.
    Returns a tuple of (ssl_config, temp_cert_file) where temp_cert_file is None if no temporary file was created.
    """
    temp_cert_file = None

    if jira_ssl_certificate_pem:
        # Create a temporary file for the certificate
        temp_cert_file = tempfile.NamedTemporaryFile(mode="w", delete=False)

        # First, remove any existing headers/footers and clean up the content
        cert_content = jira_ssl_certificate_pem.replace("\n", "").replace(" ", "")
        cert_content = cert_content.replace("-----BEGINCERTIFICATE-----", "").replace(
            "-----ENDCERTIFICATE-----", ""
        )
        cert_content = cert_content.replace("-----BEGIN CERTIFICATE-----", "").replace(
            "-----END CERTIFICATE-----", ""
        )

        # Format with proper line breaks (64 characters per line)
        formatted_body = "\n".join(
            [cert_content[i : i + 64] for i in range(0, len(cert_content), 64)]
        )

        # Add proper headers and footers
        cert_content = f"-----BEGIN CERTIFICATE-----\n{formatted_body}\n-----END CERTIFICATE-----\n"

        temp_cert_file.write(cert_content)
        temp_cert_file.close()
        ssl_config = temp_cert_file.name

    elif jira_ssl_certificate_path and os.path.isfile(jira_ssl_certificate_path):
        ssl_config = str(jira_ssl_certificate_path)
    else:
        ssl_config = True

    return ssl_config, temp_cert_file


def jira_handle_ssl_certificate(jira_ssl_certificate_path, jira_ssl_certificate_pem):
    """
    Handle SSL certificate configuration.
    Returns a tuple of (ssl_config, temp_cert_file) where temp_cert_file is None if no temporary file was created.
    """
    temp_cert_file = None

    if jira_ssl_certificate_pem:
        # Create a temporary file for the certificate
        temp_cert_file = tempfile.NamedTemporaryFile(mode="w", delete=False)

        # First, remove any existing headers/footers and clean up the content
        cert_content = jira_ssl_certificate_pem.replace("\n", "").replace(" ", "")
        cert_content = cert_content.replace("-----BEGINCERTIFICATE-----", "").replace(
            "-----ENDCERTIFICATE-----", ""
        )
        cert_content = cert_content.replace("-----BEGIN CERTIFICATE-----", "").replace(
            "-----END CERTIFICATE-----", ""
        )

        # Format with proper line breaks (64 characters per line)
        formatted_body = "\n".join(
            [cert_content[i : i + 64] for i in range(0, len(cert_content), 64)]
        )

        # Add proper headers and footers
        cert_content = f"-----BEGIN CERTIFICATE-----\n{formatted_body}\n-----END CERTIFICATE-----\n"

        temp_cert_file.write(cert_content)
        temp_cert_file.close()
        ssl_config = temp_cert_file.name

    elif jira_ssl_certificate_path and os.path.isfile(jira_ssl_certificate_path):
        ssl_config = str(jira_ssl_certificate_path)
    else:
        ssl_config = True

    return ssl_config, temp_cert_file
