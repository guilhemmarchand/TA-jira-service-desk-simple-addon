# encoding = utf-8

# Standard library imports
import csv
import gzip
import hashlib
import json
import os
import sys
import platform
import re
import tempfile
import time
import uuid
from time import localtime, strftime

# Third-party imports
import openpyxl
import requests
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE

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
)


def reformat_customfields(i):
    """
    Reformats custom fields in JIRA issue data to ensure proper JSON formatting.

    Args:
        i (str): The input string containing custom field data

    Returns:
        str: The reformatted string with proper JSON formatting for custom fields

    The function handles:
    - Custom field number formatting
    - Value formatting for single and array values
    - Backslash escaping
    - JSON structure cleanup
    """
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
        i = re.sub(r"\\\"$", '"', i)
        i = re.sub(r"\\\"\,$", '"', i)
        i = re.sub(r"\\\"\\n$", '"', i)
        i = re.sub(r"\\\"\,\\n$", '"', i)
        i = re.sub(r"(\d*),$", r"\1", i)
        i = re.sub(r"(\d*),\\n$", r"\1", i)
        i = re.sub(r"(\d*)\\n$", r"\1", i)
        # generic replacement
        i = re.sub(r"\\\"(\w*)\\\":\s\\\"([^\"]*)\"", r'"\1": "\2"', i)
        i = re.sub(r"\\\"(\w*)\\\":\s(\[{[^\}]*)", r'"\1": \2', i)
        i = re.sub(r"\\\"(\w*)\\\":\s(\[\s{[^\}]*)", r'"\1": \2', i)

        # any non escaped backslash
        i = re.sub(r"\\([^\\])", r"\\\\\1", i)

        # ending json with extra comma
        i = re.sub(r"},$", "}", i)

        return i


def json_to_jira_table(json_data):
    """
    Converts JSON data to a JIRA-formatted markdown table.

    Args:
        json_data (dict or list): The JSON data to convert. Can be a single dictionary or list of dictionaries.

    Returns:
        str: A JIRA-formatted markdown table string with headers in bold

    The function:
    - Extracts headers from dictionary keys
    - Creates a bold header row
    - Formats data rows
    - Combines into a complete table
    """
    # Ensure json_data is a list of dictionaries
    if isinstance(json_data, dict):
        json_data = [json_data]

    if not json_data:
        return ""

    # Extract the headers from the keys of the first dictionary
    headers = json_data[0].keys()

    # Create the header row in bold
    header_row = f"| {' | '.join(f'*{header}*' for header in headers)} |"

    # Create the data rows
    rows = []
    for entry in json_data:
        row = f"| {' | '.join(str(entry.get(header, '')) for header in headers)} |"
        rows.append(row)

    # Combine all parts into the final table
    table = f"{header_row}\n" + "\n".join(rows)

    return table


def reformat_customfields_minimal(i):
    """
    Performs minimal reformatting of custom fields by only removing escaped double quotes.

    Args:
        i (str): The input string containing custom field data

    Returns:
        str: The minimally reformatted string with proper escaping

    This function is used when full custom field parsing is disabled.
    """
    if i is not None:
        i = re.sub(r'\\"', '"', i)
        # any non escaped backslash
        i = re.sub(r"\\([^\\])", r"\\\\\1", i)
        # ending json with extra comma
        i = re.sub(r"},$", "}", i)

        return i


def process_event(helper, *args, **kwargs):
    # Start
    helper.set_log_level(helper.log_level)
    helper.log_info("Alert action jira_service_desk started.")

    # Get account
    account = helper.get_param("account")

    # Retrieve the session_key
    helper.log_debug("Get session_key.")
    session_key = helper.session_key

    # server_uri
    server_uri = helper.settings["server_uri"]

    # get conf
    jira_conf = jira_get_conf(session_key, server_uri)

    # get proxy configuration
    proxy_conf = jira_conf["proxy"]
    proxy_dict = proxy_conf.get("proxy_dict", {})

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

    # Build the authentication header for JIRA
    jira_headers = jira_build_headers(jira_auth_mode, jira_username, jira_password)

    # Splunk Cloud vetting notes: SSL verification is always true or the path to the CA bundle for the SSL certificate to be verified
    ssl_config, temp_cert_file = jira_handle_ssl_certificate(
        jira_ssl_certificate_path, jira_ssl_certificate_pem
    )

    # test connectivity systematically but do not fail as the resilient tracker will retry
    try:
        jira_test_connectivity(session_key, server_uri, account)
    except Exception as e:
        helper.log_error(
            f"Failed to test connectivity to Jira, account={account}, exception={str(e)}"
        )

    # Get Passthrough mode
    jira_passthrough_mode = int(
        jira_conf["advanced_configuration"].get("jira_passthrough_mode", 0)
    )
    helper.log_debug(f"passthrough_mode={jira_passthrough_mode}")

    # call the query URL REST Endpoint and pass the url and API token
    content = query_url(
        helper,
        account=account,
        jira_url=jira_url,
        jira_headers=jira_headers,
        ssl_config=ssl_config,
        proxy_dict=proxy_dict,
        jira_passthrough_mode=jira_passthrough_mode,
    )

    return 0


def get_timestr():
    """
    Returns the current time as a formatted string.

    Returns:
        str: Current time formatted as 'YYYY-MM-DD-HHMMSS'
    """
    timestr = strftime("%Y-%m-%d-%H%M%S", localtime())

    return timestr


def get_tempdir():
    """
    Gets or creates a temporary directory for file operations.

    Returns:
        str: Path to the temporary directory

    The function:
    - Detects the operating system
    - Creates the directory if it doesn't exist
    - Handles Windows and Unix paths differently
    """
    # If running Windows OS (used for directory identification)
    is_windows = re.match(r"^win\w+", (platform.system().lower()))

    # SPLUNK_HOME environment variable
    SPLUNK_HOME = os.environ["SPLUNK_HOME"]

    # define the directory for temp files
    if is_windows:
        tempdir = f"{SPLUNK_HOME}\\etc\\apps\\TA-jira-service-desk-simple-addon\\tmp"
    else:
        tempdir = f"{SPLUNK_HOME}/etc/apps/TA-jira-service-desk-simple-addon/tmp"
    if not os.path.exists(tempdir):
        os.mkdir(tempdir)

    return tempdir


def clean_tempdir(helper):
    """
    Cleans up old files from the temporary directory.

    Args:
        helper: The helper object for logging

    The function:
    - Removes files older than 300 seconds
    - Handles Windows file cleanup issues
    - Logs cleanup failures
    """
    import os
    import glob
    import time

    # Get tempdir
    tempdir = get_tempdir()

    # Enter dir
    if os.path.exists(tempdir):
        # cd to directory
        os.chdir(tempdir)
        # loop and clean
        for xfile in glob.glob("*"):
            filemtime = os.path.getmtime(xfile)
            if time.time() - filemtime > 300:
                try:
                    os.remove(xfile)
                except Exception as e:
                    helper.log_debug(
                        f"Temporary file {xfile} could not be removed, we will try another chance later on"
                    )


def attach_csv(
    helper,
    jira_url,
    jira_created_key,
    jira_attachment_token,
    jira_headers_attachment,
    ssl_config,
    proxy_dict,
    timeout,
    *args,
    **kwargs,
):
    """
    Attaches a CSV file to a JIRA issue.

    Args:
        helper: The helper object for logging
        jira_url (str): The base JIRA URL
        jira_created_key (str): The JIRA issue key
        jira_attachment_token (str): The attachment token
        jira_headers_attachment (dict): Headers for the attachment request
        ssl_config: SSL configuration
        proxy_dict (dict): Proxy configuration
        timeout (int): Request timeout in seconds

    The function:
    - Creates a temporary CSV file
    - Filters out __mv_ fields
    - Uploads the file to JIRA
    - Cleans up temporary files
    """
    # Get tempdir
    tempdir = get_tempdir()

    # Clean tempdir
    clean_tempdir(helper)

    timestr = get_timestr()
    results_csv = tempfile.NamedTemporaryFile(
        mode="w+t",
        prefix=f"splunk_alert_results_{timestr}_",
        suffix=".csv",
        dir=tempdir,
        delete=False,
    )
    jira_url = f"{jira_url}/{jira_created_key}/attachments"

    input_file = gzip.open(jira_attachment_token, "rt")
    reader = csv.DictReader(input_file)

    # filter fields (headers) starting with "__mv_"
    fieldnames = [name for name in reader.fieldnames if not name.startswith("__mv_")]

    writer = csv.DictWriter(results_csv, fieldnames=fieldnames)
    writer.writeheader()

    # filter out "__mv_" fields in rows
    for row in reader:
        row = {k: v for k, v in row.items() if not k.startswith("__mv_")}
        writer.writerow(row)

    results_csv.seek(0)

    try:
        files = {"file": open(results_csv.name, "rb")}
        response = requests.post(
            jira_url,
            files=files,
            headers=jira_headers_attachment,
            verify=ssl_config,
            proxies=proxy_dict,
            timeout=timeout,
        )
        helper.log_debug(f"response status_code:={response.status_code}")

        if response.status_code not in (200, 201, 204):
            helper.log_error(
                f"JIRA Service Desk ticket attachment file upload has failed!. url={jira_url}, "
                f"jira_attachment_token={jira_attachment_token}, HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
        else:
            helper.log_info(
                f"JIRA Service Desk ticket attachment file uploaded successfully. {jira_url},"
                f" content={response.text}"
            )

    # any exception such as proxy error, dns failure etc. will be catch here
    except Exception as e:
        helper.log_error(
            f"JIRA Service Desk ticket attachment file upload has failed!:{str(e)}"
        )

    finally:
        results_csv.close()

        # try clean
        try:
            if os.path.isfile(results_csv.name):
                os.remove(results_csv.name)
        except Exception as e:
            helper.log_debug(
                f"Temporary file {results_csv.name} could not be removed, unfortunately this is expected under Windows host guests"
            )


def attach_json(
    helper,
    jira_url,
    jira_created_key,
    jira_attachment_token,
    jira_headers_attachment,
    ssl_config,
    proxy_dict,
    timeout,
    *args,
    **kwargs,
):
    """
    Attaches a JSON file to a JIRA issue.

    Args:
        helper: The helper object for logging
        jira_url (str): The base JIRA URL
        jira_created_key (str): The JIRA issue key
        jira_attachment_token (str): The attachment token
        jira_headers_attachment (dict): Headers for the attachment request
        ssl_config: SSL configuration
        proxy_dict (dict): Proxy configuration
        timeout (int): Request timeout in seconds

    The function:
    - Converts CSV data to JSON
    - Filters out __mv_ fields
    - Uploads the file to JIRA
    - Cleans up temporary files
    """
    # Get tempdir
    tempdir = get_tempdir()

    # Clean tempdir
    clean_tempdir(helper)

    timestr = get_timestr()
    results_csv = tempfile.NamedTemporaryFile(
        mode="w+t",
        prefix=f"splunk_alert_results_{timestr}_",
        suffix=".csv",
        dir=tempdir,
        delete=False,
    )
    results_json = tempfile.NamedTemporaryFile(
        mode="w+t",
        prefix=f"splunk_alert_results_{timestr}_",
        suffix=".json",
        dir=tempdir,
        delete=False,
    )
    jira_url = f"{jira_url}/{jira_created_key}/attachments"

    input_file = gzip.open(jira_attachment_token, "rt")
    all_data = input_file.read()
    results_csv.writelines(str(all_data))
    results_csv.seek(0)

    # Convert CSV to JSON
    reader = csv.DictReader(open(results_csv.name))
    # filter out "__mv_" fields in rows
    data = [
        {k: v for k, v in row.items() if not k.startswith("__mv_")} for row in reader
    ]
    results_json.writelines(json.dumps(data, indent=2, ensure_ascii=False))
    results_json.seek(0)

    try:
        files = {"file": open(results_json.name, "rb")}
        response = requests.post(
            jira_url,
            files=files,
            headers=jira_headers_attachment,
            verify=ssl_config,
            proxies=proxy_dict,
            timeout=timeout,
        )

        helper.log_debug(f"response status_code:={response.status_code}")

        if response.status_code not in (200, 201, 204):
            helper.log_error(
                f"JIRA Service Desk ticket attachment file upload has failed!. url={jira_url}, "
                f"jira_attachment_token={jira_attachment_token}, HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
        else:
            helper.log_info(
                f"JIRA Service Desk ticket attachment file uploaded successfully. {jira_url},"
                f" content={response.text}"
            )

    # any exception such as proxy error, dns failure etc. will be catch here
    except Exception as e:
        helper.log_error(
            f"JIRA Service Desk ticket attachment file upload has failed!:{str(e)}"
        )

    finally:
        results_csv.close()
        results_json.close()

        # try clean
        try:
            if os.path.isfile(results_csv.name):
                os.remove(results_csv.name)
        except Exception as e:
            helper.log_debug(
                f"Temporary file {results_csv.name}could not be removed, unfortunately this is expected under Windows host guests"
            )

        # try clean
        try:
            if os.path.isfile(results_json.name):
                os.remove(results_json.name)
        except Exception as e:
            helper.log_debug(
                f"Temporary file {results_json.name} could not be removed, unfortunately this is expected under Windows host guests"
            )


def attach_xlsx(
    helper,
    jira_url,
    jira_created_key,
    jira_attachment_token,
    jira_headers_attachment,
    ssl_config,
    proxy_dict,
    timeout,
    *args,
    **kwargs,
):
    """
    Attaches an Excel (XLSX) file to a JIRA issue.

    Args:
        helper: The helper object for logging
        jira_url (str): The base JIRA URL
        jira_created_key (str): The JIRA issue key
        jira_attachment_token (str): The attachment token
        jira_headers_attachment (dict): Headers for the attachment request
        ssl_config: SSL configuration
        proxy_dict (dict): Proxy configuration
        timeout (int): Request timeout in seconds

    The function:
    - Converts CSV data to XLSX format
    - Filters out __mv_ fields
    - Handles illegal characters
    - Uploads the file to JIRA
    - Cleans up temporary files
    """
    # Get tempdir
    tempdir = get_tempdir()

    # Clean tempdir
    clean_tempdir(helper)

    timestr = get_timestr()
    results_csv = tempfile.NamedTemporaryFile(
        mode="w+t",
        prefix=f"splunk_alert_results_{timestr}_",
        suffix=".csv",
        dir=tempdir,
        delete=False,
    )
    results_xlsx = tempfile.NamedTemporaryFile(
        mode="w+t",
        prefix=f"splunk_alert_results_{timestr}_",
        suffix=".xlsx",
        dir=tempdir,
        delete=False,
    )
    jira_url = f"{jira_url}/{jira_created_key}/attachments"

    input_file = gzip.open(jira_attachment_token, "rt")
    all_data = input_file.read()
    results_csv.writelines(str(all_data))
    results_csv.seek(0)

    # convert csv to xlsx
    wb = openpyxl.Workbook()
    ws = wb.active

    reader = csv.reader(open(results_csv.name), delimiter=",")
    count = 0
    excluded_indices = []
    for row in reader:
        count += 1
        if count == 1:
            # check for columns starting with "__mv_"
            for i, cell in enumerate(row):
                if cell.startswith("__mv_"):
                    excluded_indices.append(i)
            # only append non-excluded cells
            ws.append(
                [
                    ILLEGAL_CHARACTERS_RE.sub("", cell)
                    for i, cell in enumerate(row)
                    if i not in excluded_indices
                ]
            )
        else:
            # only append non-excluded cells
            ws.append([cell for i, cell in enumerate(row) if i not in excluded_indices])

    wb.save(results_xlsx.name)
    results_xlsx.seek(0)

    try:
        files = {"file": open(results_xlsx.name, "rb")}
        response = requests.post(
            jira_url,
            files=files,
            headers=jira_headers_attachment,
            verify=ssl_config,
            proxies=proxy_dict,
            timeout=timeout,
        )
        helper.log_debug(f"response status_code:={response.status_code}")

        if response.status_code not in (200, 201, 204):
            helper.log_error(
                f"JIRA Service Desk ticket attachment file upload has failed!. url={jira_url}, "
                f"jira_attachment_token={jira_attachment_token}, HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
        else:
            helper.log_info(
                f"JIRA Service Desk ticket attachment file uploaded successfully. {jira_url},"
                f" content={response.text}"
            )

    # any exception such as proxy error, dns failure etc. will be catch here
    except Exception as e:
        helper.log_error(
            f"JIRA Service Desk ticket attachment file upload has failed!:{str(e)}"
        )

    finally:
        results_csv.close()
        results_xlsx.close()

        # try clean
        try:
            if os.path.isfile(results_csv.name):
                os.remove(results_csv.name)
        except Exception as e:
            helper.log_debug(
                f"Temporary file {results_csv.name} could not be removed, unfortunately this is expected under Windows host guests"
            )

        # try clean
        try:
            if os.path.isfile(results_xlsx.name):
                os.remove(results_xlsx.name)
        except Exception as e:
            helper.log_debug(
                f"Temporary file {results_xlsx.name} could not be removed, unfortunately this is expected under Windows host guests"
            )


def get_results_json(helper, jira_attachment_token, *args, **kwargs):
    """
    Retrieves search results as JSON from a JIRA attachment token.

    Args:
        helper: The helper object for logging
        jira_attachment_token (str): The attachment token

    Returns:
        str: The JSON-formatted search results
        None: If an error occurs

    The function:
    - Reads gzipped CSV data
        helper: The helper object for logging and HTTP requests
        jira_url: The base Jira URL
        jira_headers: Headers for Jira API requests
        ssl_config: SSL configuration
        proxy_dict: Proxy configuration
        event: The event data containing field values
        jira_auto_close: Whether auto-closure is enabled
        jira_auto_close_key_value_pair: The key-value pair to check for auto-closure
        jira_auto_close_status_transition_value: The target status for transition
        jira_auto_close_issue_number_field_name: The field name containing the issue number
        jira_auto_close_status_transition_comment: The comment to add when performing the transition
        jira_backlog_key: The Jira issue key from deduplication (if available)
    """
    # Skip if auto-closure is not enabled
    if jira_auto_close != "enabled":
        helper.log_debug("Auto-closure is not enabled, skipping")
        return

    # Skip if key-value pair is not provided
    if not jira_auto_close_key_value_pair:
        helper.log_debug("Auto-closure key-value pair not provided, skipping")
        return

    # Parse the key-value pair
    try:
        key, value = jira_auto_close_key_value_pair.split("=")
    except ValueError:
        helper.log_error(
            f"Invalid auto-closure key-value pair format: {jira_auto_close_key_value_pair}"
        )
        return

    # Check if the event contains the required key-value pair
    if key not in event or event[key] != value:
        helper.log_debug(
            f"Event does not contain required key-value pair: {key}={value}"
        )
        return

    # Get the issue key/ID
    issue_key = None
    if jira_backlog_key:  # If we have a backlog key from dedup
        issue_key = jira_backlog_key
    elif (
        jira_auto_close_issue_number_field_name
        and jira_auto_close_issue_number_field_name in event
    ):
        issue_key = event[jira_auto_close_issue_number_field_name]

    if not issue_key:
        helper.log_error("Could not determine Jira issue key for auto-closure")
        return

    # Step 1: Get available transitions
    transitions_url = f"{jira_url}/{issue_key}/transitions"
    try:
        response = requests.get(
            transitions_url,
            headers=jira_headers,
            verify=ssl_config,
            proxies=proxy_dict,
            timeout=timeout,
        )

        if response.status_code not in (200, 201, 204):
            helper.log_error(
                f"Failed to get transitions for issue {issue_key}: {response.text}"
            )
            return

        transitions_data = json.loads(response.text)
        target_transition = None

        # Find the transition matching the target status
        for transition in transitions_data.get("transitions", []):
            if (
                transition.get("to", {}).get("name")
                == jira_auto_close_status_transition_value
            ):
                target_transition = transition
                break

        if not target_transition:
            helper.log_error(
                f"Could not find transition to status: {jira_auto_close_status_transition_value}"
            )
            return

        # Step 2: Perform the transition
        transition_url = f"{jira_url}/{issue_key}/transitions"

        # Use custom comment if provided, otherwise use default
        base_comment = (
            f"Auto-closure triggered by Splunk alert action. Condition: {key}={value}"
        )
        comment = (
            f"{base_comment} - {jira_auto_close_status_transition_comment}"
            if jira_auto_close_status_transition_comment
            else base_comment
        )

        transition_data = {
            "transition": {"id": target_transition["id"]},
            "update": {"comment": [{"add": {"body": comment}}]},
        }

        response = requests.post(
            transition_url,
            json=transition_data,
            headers=jira_headers,
            verify=ssl_config,
            proxies=proxy_dict,
            timeout=timeout,
        )

        if response.status_code not in (200, 201, 204):
            helper.log_error(f"Failed to transition issue {issue_key}: {response.text}")
            return

        helper.log_info(
            f"Successfully transitioned issue {issue_key} to {jira_auto_close_status_transition_value}"
        )

        # Step 3: Add a separate comment using the comment API endpoint
        comment_url = f"{jira_url}/{issue_key}/comment"
        comment_data = {"body": comment}

        response = requests.post(
            comment_url,
            json=comment_data,
            headers=jira_headers,
            verify=ssl_config,
            proxies=proxy_dict,
            timeout=timeout,
        )

        if response.status_code not in (200, 201, 204):
            helper.log_error(
                f"Failed to add comment to issue {issue_key}: {response.text}"
            )
            return

        helper.log_info(f"Successfully added comment to issue {issue_key}")

    except Exception as e:
        helper.log_error(f"Error during auto-closure process: {str(e)}")
