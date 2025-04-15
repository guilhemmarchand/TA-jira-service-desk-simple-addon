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
    Retrieves the system-wide configuration using a least privilege approach.

    Args:
        session_key (str): The Splunk session key for authentication
        splunkd_uri (str): The URI of the Splunk server

    Returns:
        dict: The configuration data as a JSON object

    Raises:
        Exception: If the configuration retrieval fails
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
    Retrieves the list of configured JIRA accounts using a least privilege approach.

    Args:
        session_key (str): The Splunk session key for authentication
        splunkd_uri (str): The URI of the Splunk server

    Returns:
        dict: The list of accounts as a JSON object

    Raises:
        Exception: If the account list retrieval fails
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
    Retrieves account credentials for a specific JIRA account using a least privilege approach.

    Args:
        session_key (str): The Splunk session key for authentication
        splunkd_uri (str): The URI of the Splunk server
        account (str): The name of the account to retrieve

    Returns:
        dict: The account credentials as a JSON object

    Raises:
        Exception: If the account retrieval fails
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
    Tests connectivity to a JIRA instance using the configured account.

    Args:
        session_key (str): The Splunk session key for authentication
        splunkd_uri (str): The URI of the Splunk server
        account (str): The name of the account to test

    Returns:
        dict: The connectivity test results as a JSON object

    Raises:
        Exception: If the connectivity test fails
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
    """
    Retrieves a bearer token for authentication with JIRA.

    Args:
        session_key (str): The Splunk session key for authentication
        splunkd_uri (str): The URI of the Splunk server

    Returns:
        str: The bearer token

    Raises:
        Exception: If the bearer token retrieval fails
    """

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
    Builds JIRA headers based on the specified authentication mode.

    Args:
        jira_auth_mode (str): The authentication mode ('basic' or 'pat')
        jira_username (str): The JIRA username (for basic auth)
        jira_password (str): The JIRA password or personal access token

    Returns:
        dict: The constructed headers for JIRA API requests

    Raises:
        Exception: If an invalid authentication mode is provided
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
    Builds SSL configuration for JIRA connection.

    Args:
        jira_ssl_certificate_path (str): Path to the SSL certificate file
        jira_ssl_certificate_pem (str, optional): PEM-encoded certificate content
        account_name (str, optional): Name of the account for logging purposes

    Returns:
        tuple: A tuple containing (ssl_config, temp_cert_file)
            - ssl_config: The SSL configuration for requests
            - temp_cert_file: The temporary certificate file path if created

    Raises:
        Exception: If SSL configuration fails
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
    Handles SSL certificate configuration for JIRA connection.

    Args:
        jira_ssl_certificate_path (str): Path to the SSL certificate file
        jira_ssl_certificate_pem (str, optional): PEM-encoded certificate content

    Returns:
        tuple: A tuple containing (ssl_config, temp_cert_file)
            - ssl_config: The SSL configuration for requests
            - temp_cert_file: The temporary certificate file path if created

    Raises:
        Exception: If SSL certificate handling fails
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
