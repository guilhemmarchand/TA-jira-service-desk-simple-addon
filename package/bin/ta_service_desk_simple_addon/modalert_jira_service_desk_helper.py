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


# This function is required to reformat proper values in the custom fields
def reformat_customfields(i):
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


# This function is used to format a markdown table from json table in description
def json_to_jira_table(json_data):
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


# This function can optionnally be used to only remove the espaced double quotes and leave the custom fields with no parsing at all
def reformat_customfields_minimal(i):
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


# simple def to return current time for file naming
def get_timestr():
    timestr = strftime("%Y-%m-%d-%H%M%S", localtime())

    return timestr


def get_tempdir():
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


# This function is made necessary due to Windows incapability to purge temporary files properly, as other serious OS would
def clean_tempdir(helper):
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
    try:
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

        input_file = gzip.open(jira_attachment_token, "rt")
        all_data = input_file.read()
        results_csv.writelines(str(all_data))
        results_csv.seek(0)

        # Convert CSV to JSON
        reader = csv.DictReader(open(results_csv.name))
        # filter out "__mv_" fields in rows
        data = [
            {k: v for k, v in row.items() if not k.startswith("__mv_")}
            for row in reader
        ]
        results_json.writelines(json.dumps(data, indent=2, ensure_ascii=False))
        results_json.seek(0)

        return results_json.read()

    except Exception as e:
        helper.log_error(
            f'function get_results_json has failed with exception="{str(e)}"'
        )
        return None


def get_results_csv(helper, jira_attachment_token, *args, **kwargs):
    try:
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

        input_file = gzip.open(jira_attachment_token, "rt")
        reader = csv.DictReader(input_file)

        # filter fields (headers) starting with "__mv_"
        fieldnames = [
            name for name in reader.fieldnames if not name.startswith("__mv_")
        ]

        writer = csv.DictWriter(results_csv, fieldnames=fieldnames)
        writer.writeheader()

        # filter out "__mv_" fields in rows
        for row in reader:
            row = {k: v for k, v in row.items() if not k.startswith("__mv_")}
            writer.writerow(row)

        results_csv.seek(0)

        return results_csv.read()

    except Exception as e:
        helper.log_error(
            f'function get_results_csv has failed with exception="{str(e)}"'
        )
        return None


def query_url(
    helper,
    account,
    jira_url=None,
    jira_headers=None,
    ssl_config=None,
    proxy_dict=None,
    jira_passthrough_mode=None,
):
    # Retrieve the session_key
    helper.log_debug("Get session_key.")
    session_key = helper.session_key

    # splunkd_uri
    splunkd_uri = helper.settings["server_uri"]

    # get conf
    jira_conf = jira_get_conf(session_key, splunkd_uri)

    # set timeout
    timeout = int(jira_conf["advanced_configuration"].get("timeout", 120))

    # For Splunk Cloud vetting, the URL must start with https://
    if not jira_url.startswith("https://"):
        jira_url = f"https://{jira_url}/rest/api/latest/issue"
    else:
        jira_url = f"{jira_url}/rest/api/latest/issue"
    # keep this url as a super url
    jira_root_url = jira_url

    # Retrieve parameters which are not event related
    jira_project = helper.get_param("jira_project")
    helper.log_debug(f"jira_project={jira_project}")

    jira_issue_type = helper.get_param("jira_issue_type")
    helper.log_debug(f"jira_issue_type={jira_issue_type}")

    jira_priority = helper.get_param("jira_priority")
    helper.log_debug(f"jira_priority={jira_priority}")

    jira_dedup_enabled = False
    jira_dedup = helper.get_param("jira_dedup")
    if jira_dedup == "enabled":
        jira_dedup_enabled = True
    helper.log_debug(f"jira_dedup_enabled={jira_dedup_enabled}")

    jira_dedup_comment = helper.get_param("jira_dedup_comment")

    jira_dedup_exclude_statuses = helper.get_param("jira_dedup_exclude_statuses")
    if jira_dedup_exclude_statuses in ["", "None", None]:
        jira_dedup_exclude_statuses = "Done"
    helper.log_debug(f"jira_dedup_exclude_statuses={jira_dedup_exclude_statuses}")
    # needs to be converted to an array for later processing
    jira_dedup_exclude_statuses = jira_dedup_exclude_statuses.split(",")

    jira_dedup_content = helper.get_param("jira_dedup_content")
    if jira_dedup_content in ["", "None", None]:
        jira_dedup_full_mode = True
        helper.log_debug(
            "jira_dedup: jira_dedup_full_mode is set to True, the full issue data will be used"
            " for the sha256 calculation."
        )
    else:
        jira_dedup_full_mode = False
        helper.log_debug(
            "jira_dedup: jira_dedup_full_mode is set to False, the sha256 calculation scope will be restricted"
            " to the content of the jira_dedup_content."
        )
        helper.log_debug(f"jira_dedup_content={jira_dedup_content}")

    jira_attachment = helper.get_param("jira_attachment")
    helper.log_debug(f"jira_attachment={jira_attachment}")

    if jira_attachment in ["", "None", None]:
        jira_attachment = "disabled"
    helper.log_debug(f"jira_attachment:={jira_attachment}")

    jira_attachment_token = helper.get_param("jira_attachment_token")
    helper.log_debug(f"jira_attachment_token={jira_attachment_token}")

    jira_results_description = helper.get_param("jira_results_description")
    helper.log_debug(f"jira_results_description={jira_results_description}")

    if jira_results_description in ["", "None", None]:
        jira_results_description = "disabled"
    helper.log_debug(f"jira_results_description:={jira_results_description}")

    jira_customfields_parsing = helper.get_param("jira_customfields_parsing")
    helper.log_debug(f"jira_customfields_parsing={jira_customfields_parsing}")

    if jira_customfields_parsing in ["", "None", None]:
        jira_customfields_parsing = "enabled"
    helper.log_debug(f"jira_customfields_parsing:={jira_customfields_parsing}")

    # headers for attachments
    jira_headers_attachment = jira_headers
    jira_headers_attachment["X-Atlassian-Token"] = "no-check"
    # remove the content-type header
    jira_headers_attachment.pop("Content-Type", None)

    #
    # Auto close capabilities
    #
    jira_auto_close = helper.get_param("jira_auto_close")
    jira_auto_close_key_value_pair = helper.get_param("jira_auto_close_key_value_pair")
    jira_auto_close_status_transition_value = helper.get_param(
        "jira_auto_close_status_transition_value"
    )
    jira_auto_close_status_transition_comment = helper.get_param(
        "jira_auto_close_status_transition_comment"
    )
    jira_auto_close_issue_number_field_name = helper.get_param(
        "jira_auto_close_issue_number_field_name"
    )
    helper.log_debug(
        f"auto-close parameters: jira_auto_close={jira_auto_close}, jira_auto_close_key_value_pair={jira_auto_close_key_value_pair}, jira_auto_close_status_transition_value={jira_auto_close_status_transition_value}, jira_auto_close_issue_number_field_name={jira_auto_close_issue_number_field_name}"
    )

    # Loop within events and proceed
    events = helper.get_events()
    for event in events:
        helper.log_debug(f"event={event}")

        jira_priority_dynamic = helper.get_param("jira_priority_dynamic")
        helper.log_debug(f"jira_priority_dynamic={jira_priority_dynamic}")

        jira_summary = helper.get_param("jira_summary")
        helper.log_debug(f"jira_summary={jira_summary}")

        jira_description = helper.get_param("jira_description")
        helper.log_debug(f"jira_description={jira_description}")

        jira_assignee = helper.get_param("jira_assignee")
        helper.log_debug(f"jira_assignee={jira_assignee}")

        jira_reporter = helper.get_param("jira_reporter")
        helper.log_debug(f"jira_reporter={jira_reporter}")

        jira_labels = helper.get_param("jira_labels")
        helper.log_debug(f"jira_labels={jira_labels}")

        jira_components = helper.get_param("jira_components")
        helper.log_debug(f"jira_components={jira_components}")

        # Retrieve the custom fields
        jira_customfields = helper.get_param("jira_customfields")
        helper.log_debug(f"jira_customfields={jira_customfields}")

        # custom fields parsing is function of the alert configuration and can be disabled on demand
        if jira_customfields_parsing not in ("disabled"):
            helper.log_info(f"jira_customfields_parsing={jira_customfields_parsing}")
            jira_customfields = reformat_customfields(jira_customfields)
        else:
            helper.log_info(f"jira_customfields_parsing={jira_customfields_parsing}")
            jira_customfields = reformat_customfields_minimal(jira_customfields)
        helper.log_debug(f"jira_customfields={jira_customfields}")

        # Manage custom fields properly

        data = {}

        # add project
        data["fields"] = {"project": {"key": jira_project}}

        # add summary
        data["fields"]["summary"] = jira_summary

        # add description

        # if user requested, add the results
        if jira_results_description in ("enabled_json"):
            search_results_json = get_results_json(helper, jira_attachment_token)
            if search_results_json:
                jira_description = (
                    jira_description
                    + "\nSplunk search results:\n{code:json}"
                    + search_results_json
                    + "\n{code}"
                )

        elif jira_results_description in ("enabled_csv"):
            search_results_csv = get_results_csv(helper, jira_attachment_token)
            if search_results_csv:
                jira_description = (
                    jira_description
                    + "\nSplunk search results:\n{code:csv}"
                    + search_results_csv
                    + "\n{code}"
                )

        elif jira_results_description in ("enabled_table"):
            search_results_json = get_results_json(helper, jira_attachment_token)
            if search_results_json:
                search_result_table = json_to_jira_table(
                    json.loads(search_results_json)
                )
                jira_description = (
                    jira_description
                    + "\nSplunk search results:\n"
                    + search_result_table
                )

        data["fields"]["description"] = jira_description

        # add issue type
        data["fields"]["issuetype"] = {"name": jira_issue_type}

        # JIRA assignee
        if jira_assignee not in ["", "None", None]:
            # add assignee
            data["fields"]["assignee"] = {"accountId": jira_assignee}

        # JIRA reporter
        if jira_reporter not in ["", "None", None]:
            data["fields"]["reporter"] = {"accountId": jira_reporter}

        # Priority can be dynamically overridden by the text input dynamic priority, if set
        if jira_priority not in ["", "None", None]:
            if jira_priority_dynamic not in ["", "None", None]:
                helper.log_debug(
                    f"jira priority is overridden by "
                    f"jira_priority_dynamic={jira_priority_dynamic}"
                )
                # add
                data["fields"]["priority"] = {"name": jira_priority_dynamic}

            else:
                # add
                data["fields"]["priority"] = {"name": jira_priority}

        # labels
        if jira_labels not in ["", "None", None]:
            data["fields"]["labels"] = jira_labels.split(",")

        # components
        if jira_components not in ["", "None", None]:
            # set as a list
            jira_components_list = jira_components.split(",")
            jira_subcomponents_list = []

            # loop and format as a list of objects
            for sub_jira_component in jira_components_list:
                jira_subcomponents_list.append({"name": sub_jira_component})

            # finally add to the json data
            data["fields"]["components"] = jira_subcomponents_list

        # JIRA custom fields structure
        if jira_customfields not in ["", "None", None]:
            # Add a double quote at the start if it doesn't start with {
            if not jira_customfields.startswith("{"):
                if not jira_customfields.startswith('"'):
                    jira_customfields = '"' + jira_customfields

            # Add a double quote at the end if it doesn't end with }
            if not jira_customfields.endswith("}") and not jira_customfields.endswith(
                "]"
            ):  # added to support arrays (see: Issue#181)
                if not jira_customfields.endswith('"'):
                    jira_customfields = jira_customfields + '"'

            # set as json
            jira_customfields = "{" + jira_customfields + "}"

            try:
                jira_customfields_json = json.loads(jira_customfields)

                # Loop
                for jira_customfields_sub in jira_customfields_json:
                    data["fields"][jira_customfields_sub] = jira_customfields_json[
                        jira_customfields_sub
                    ]

            except Exception as e:
                helper.log_error(
                    f'Failed to load jira_customfields="{jira_customfields}" as a proper formated JSON object with exception="{e}"'
                )

        # log raw json in debug mode
        helper.log_debug(f'JSON payload before submission="{json.dumps(data)}"')
        helper.log_debug(
            f'JSON pretty print before submission="{json.dumps(data, indent=4)}"'
        )

        # Generate an sha256 unique hash for this issue
        # If jira_dedup_full_mode is set to True, the entire json data is used
        # Otherwise, jira_dedup_content was detected as filled and its content is used to perform the sha256 calculation
        if jira_dedup_full_mode:
            jira_sha256sum = hashlib.sha256(json.dumps(data).encode())
        else:
            jira_sha256sum = hashlib.sha256(jira_dedup_content.encode())
        jira_sha256sum = jira_sha256sum.hexdigest()
        helper.log_debug(f"jira_sha256sum:={jira_sha256sum}")

        # Initiate default behaviour
        jira_dedup_sha256_found = False
        jira_dedup_comment_issue = False

        # Verify the collection, if the collection returns a result for this sha256 as the _key, this issue
        # is a duplicate (http 200)
        record_url = (
            f"{splunkd_uri}/servicesNS/nobody/"
            "TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_issues_backlog/"
            + str(jira_sha256sum)
        )
        headers = {
            "Authorization": "Splunk %s" % session_key,
            "Content-Type": "application/json",
        }

        response = requests.get(record_url, headers=headers, verify=False)
        helper.log_debug(f"response status_code:={response.status_code}")

        if response.status_code == 200:
            if jira_dedup_enabled:
                helper.log_info(
                    f"jira_dedup: An issue with same sha256 hash ({jira_sha256sum}) was found in the backlog "
                    f"collection, as jira_dedup is enabled a new comment "
                    f"will be added if the issue is active. (status is not resolved or any other done status), entry:={response.text}"
                )
                jira_backlog_response = response.text
                jira_backlog_response_json = json.loads(jira_backlog_response)
                helper.log_debug(
                    f"jira_backlog_response_json:={jira_backlog_response_json}"
                )

                jira_backlog_id = jira_backlog_response_json["jira_id"]
                jira_backlog_key = jira_backlog_response_json["jira_key"]
                jira_backlog_kvkey = jira_backlog_response_json["_key"]
                jira_backlog_self = jira_backlog_response_json["jira_self"]
                jira_backlog_sha256 = jira_backlog_response_json["jira_sha256"]
                jira_backlog_ctime = jira_backlog_response_json["ctime"]

                helper.log_debug(f"jira_backlog_key:={jira_backlog_key}")

                # Attempt to get the current status of the issue
                # Define status url on top of jira_url

                # Define first the status to unknown, if the status is Closed a new issue will be created
                # if dedup is enabled
                jira_issue_status = "Unknown"
                jira_issue_status_category = "Unknown"
                jira_url_status = jira_url + "/" + str(jira_backlog_key)
                helper.log_debug(f"jira_url_status:={jira_url_status}")

                # Try http get, catch exceptions and incorrect http return codes
                try:
                    response = requests.get(
                        jira_url_status,
                        headers=headers,
                        verify=ssl_config,
                        proxies=proxy_dict,
                        timeout=timeout,
                    )
                    helper.log_debug(f"response status_code:={response.status_code}")

                    # No http exception, but http post was not successful
                    if response.status_code not in (200, 201, 204):
                        helper.log_error(
                            f"JIRA Service Desk get ticket status has failed!. url={jira_url_status}, data={data}, HTTP Error={response.status_code}, "
                            f"content={response.text}"
                        )

                    else:
                        jira_get_response = response.text
                        jira_get_response_json = json.loads(jira_get_response)
                        jira_issue_status = jira_get_response_json["fields"]["status"][
                            "name"
                        ]
                        jira_issue_status_category = jira_get_response_json["fields"][
                            "status"
                        ]["statusCategory"]["name"]
                        helper.log_debug(f"jira_issue_status:={jira_issue_status}")
                        helper.log_debug(
                            f"jira_issue_status_category:={jira_issue_status_category}"
                        )

                # any exception such as proxy error, dns failure etc. will be catch here
                except Exception as e:
                    helper.log_error(
                        f"JIRA Service Desk get ticket status has failed!: {str(e)}"
                    )
                    helper.log_error(f"message content={data}")
                    jira_issue_status = "Unknown"

                # If dedup is enabled and the issue status is not closed
                if (
                    jira_dedup_enabled
                    and jira_issue_status_category not in jira_dedup_exclude_statuses
                ):
                    # Log a message
                    helper.log_info(
                        f'jira_dedup: The issue with key {jira_backlog_key} was set to status: "{jira_issue_status}" (status category: "{jira_issue_status_category}"), '
                        "therefore, a new comment will be added to this issue."
                    )

                    # Check for auto-closure
                    perform_auto_closure(
                        helper,
                        jira_url,
                        jira_headers,
                        ssl_config,
                        proxy_dict,
                        timeout,
                        event,
                        jira_auto_close,
                        jira_auto_close_key_value_pair,
                        jira_auto_close_status_transition_value,
                        jira_auto_close_issue_number_field_name,
                        jira_auto_close_status_transition_comment,
                        jira_backlog_key,
                    )

                    # generate a new jira_url, and the comment
                    jira_dedup_comment_issue = True
                    jira_url = jira_url + "/" + str(jira_backlog_key) + "/comment"
                    helper.log_debug(f"jira_url:={jira_url}")

                    # Handle the JIRA comment to be added, if a field named jira_update_comment is part of the result,
                    # its content will used for the comment content.
                    jira_update_comment = {
                        "body": "New alert triggered: " + jira_summary
                    }

                    for key, value in event.items():
                        if key in "jira_update_comment":
                            jira_update_comment = {"body": value}

                    # if jira_dedup_comment is set, add it to the jira_update_comment
                    if jira_dedup_comment:
                        jira_update_comment["body"] = (
                            f'{jira_update_comment["body"]} - {jira_dedup_comment}'
                        )

                    helper.log_debug(f"jira_update_comment:={jira_update_comment}")

                    data = jira_update_comment

                    helper.log_debug(
                        f"JSON payload before submission={json.dumps(jira_update_comment)}"
                    )

                # dedup is enabled but the issue was resolved, closed or cancelled
                elif (
                    jira_dedup_enabled
                    and jira_issue_status_category in jira_dedup_exclude_statuses
                ):
                    helper.log_info(
                        f'jira_dedup: The issue with key {jira_backlog_key} has the same MD5 hash: {jira_backlog_sha256} and its status was set to: "{jira_issue_status}" (status category: "{jira_issue_status_category}"), a new comment will not be added to an issue in this status, therefore a new issue will be created.'
                    )

                    # Remove this issue from the backlog collection
                    record_url = (
                        f"{splunkd_uri}/servicesNS/nobody/"
                        "TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_issues_backlog"
                    )
                    headers = {
                        "Authorization": "Splunk %s" % session_key,
                        "Content-Type": "application/json",
                    }

                    response = requests.delete(
                        record_url + "/" + jira_sha256sum, headers=headers, verify=False
                    )

                    if response.status_code not in (200, 201, 204):
                        helper.log_error(
                            f"KVstore saving has failed!. url={record_url}, data={record}, HTTP Error={response.status_code}, "
                            f"content={response.text}"
                        )
                    else:
                        helper.log_debug(
                            f"JIRA issue record in the backlog collection was successfully delete. "
                            f"content={response.text}"
                        )

                    jira_dedup_sha256_found = False

            else:
                helper.log_info(
                    f"jira_dedup: An issue with same sha256 hash ({jira_sha256sum}) was found in the backlog "
                    f"collection, as jira_dedup is not enabled a new issue "
                    f"will be created, entry:={response.text}"
                )
                jira_dedup_sha256_found = True

        else:
            helper.log_debug(
                f"jira_dedup: The calculated sha256 hash for this issue creation request ({jira_sha256sum}) was not found in the backlog collection, a new issue will be created"
            )
            jira_dedup_sha256_found = False

        # Try http post, catch exceptions and incorrect http return codes

        #
        # passthrough_mode: in this mode, the instance will not perform a real call to JIRA
        # Instead, it will use the replay KVstore and will store the json data of the REST call to be performed
        # This mode is designed to accomodate use cases such as Splunk Cloud where the Cloud instance cannot contact an on-premise JIRA deployment
        # A second search head running on-premise would recycle the replay KVstore results and perform the true call to JIRA
        #

        if jira_passthrough_mode:
            # For issue creation only
            if not jira_dedup_comment_issue:
                # Store the failed publication in the replay KVstore
                record_url = (
                    f"{splunkd_uri}/servicesNS/nobody/"
                    "TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay"
                )
                record_uuid = str(uuid.uuid1())
                headers = {
                    "Authorization": "Splunk %s" % session_key,
                    "Content-Type": "application/json",
                }

                record = {
                    "account": str(account),
                    "_key": record_uuid,
                    "ctime": str(time.time()),
                    "status": "pending",
                    "no_attempts": 0,
                    "data": json.dumps(data, indent=2),
                }

                response = requests.post(
                    record_url, headers=headers, data=json.dumps(record), verify=False
                )
                if response.status_code not in (200, 201, 204):
                    helper.log_error(
                        f"KVstore saving has failed!. url={record_url}, data={record}, HTTP Error={response.status_code}, "
                        f"content={response.text}"
                    )
                else:
                    helper.log_info(
                        f"JIRA Service Desk is running in passthrough mode, the ticket data was stored in the "
                        f"replay KVstore with uuid: {record_uuid}"
                    )

        else:
            try:
                response = requests.post(
                    jira_url,
                    json=data,
                    headers=jira_headers,
                    verify=ssl_config,
                    proxies=proxy_dict,
                    timeout=timeout,
                )
                helper.log_debug(f"response status_code:={response.status_code}")

                # No http exception, but http post was not successful
                if response.status_code not in (200, 201, 204):
                    helper.log_error(
                        f"JIRA Service Desk ticket creation has failed!. url={jira_url}, data={data}, HTTP Error={response.status_code}, "
                        f"content={response.text}"
                    )

                    # For issue creation only
                    if not jira_dedup_comment_issue:
                        record_url = (
                            f"{splunkd_uri}/servicesNS/nobody/"
                            "TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay"
                        )
                        record_uuid = str(uuid.uuid1())
                        helper.log_error(
                            f"JIRA Service Desk failed ticket stored for next chance replay purposes in the "
                            f"replay KVstore with uuid: {record_uuid}"
                        )
                        headers = {
                            "Authorization": "Splunk %s" % session_key,
                            "Content-Type": "application/json",
                        }

                        record = {
                            "account": str(account),
                            "_key": record_uuid,
                            "ctime": str(time.time()),
                            "status": "temporary_failure",
                            "no_attempts": 1,
                            "data": json.dumps(data, indent=2),
                        }

                        response = requests.post(
                            record_url,
                            headers=headers,
                            data=json.dumps(record),
                            verify=False,
                        )
                        if response.status_code not in (200, 201, 204):
                            helper.log_error(
                                f"KVstore saving has failed!. url={record_url}, data={record}, HTTP Error={response.status_code}, "
                                f"content={response.text}"
                            )

                    return 0

            # any exception such as proxy error, dns failure etc. will be catch here
            except Exception as e:
                helper.log_error(
                    f"JIRA Service Desk ticket creation has failed!: {str(e)}"
                )
                helper.log_error(f"message content={data}")

                # For issue creation only
                if not jira_dedup_comment_issue:
                    # Store the failed publication in the replay KVstore
                    record_url = (
                        f"{splunkd_uri}/servicesNS/nobody/"
                        "TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay"
                    )
                    record_uuid = str(uuid.uuid1())
                    helper.log_error(
                        f"JIRA Service Desk failed ticket stored for next chance replay purposes in the "
                        f"replay KVstore with uuid: {record_uuid}"
                    )
                    headers = {
                        "Authorization": "Splunk %s" % session_key,
                        "Content-Type": "application/json",
                    }

                    record = {
                        "account": str(account),
                        "_key": record_uuid,
                        "ctime": str(time.time()),
                        "status": "temporary_failure",
                        "no_attempts": 1,
                        "data": json.dumps(data, indent=2),
                    }

                    response = requests.post(
                        record_url,
                        headers=headers,
                        data=json.dumps(record),
                        verify=False,
                    )
                    if response.status_code not in (200, 201, 204):
                        helper.log_error(
                            f"KVstore saving has failed!. url={record_url}, data={record}, HTTP Error={response.status_code}, "
                            f"content={response.text}"
                        )

                return 0

            else:
                if jira_dedup_comment_issue:
                    helper.log_info(
                        f"JIRA Service Desk ticket successfully updated. {jira_url},"
                        f" content={response.text}"
                    )
                    jira_creation_response = response.text

                    # Update the backlog collection entry
                    record = {
                        "account": str(account),
                        "jira_sha256": jira_backlog_sha256,
                        "ctime": jira_backlog_ctime,
                        "mtime": time.time(),
                        "status": "updated",
                        "jira_id": jira_backlog_id,
                        "jira_key": jira_backlog_key,
                        "jira_self": jira_backlog_self,
                    }
                    record = json.dumps(record).encode("utf-8")
                    helper.log_debug(f"record={record}")

                    response = requests.post(
                        record_url, headers=headers, data=record, verify=False
                    )
                    if response.status_code not in (200, 201, 204):
                        helper.log_error(
                            f"Backlog KVstore saving has failed!. url={record_url}, data={record}, HTTP Error={response.status_code}, "
                            f"content={response.text}"
                        )
                    else:
                        helper.log_debug(
                            f"JIRA issue record in the backlog collection was successfully updated. "
                            f"content={response.text}"
                        )

                    # Manage attachment
                    if jira_attachment in ("enabled_csv"):
                        attach_csv(
                            helper,
                            jira_root_url,
                            jira_backlog_key,
                            jira_attachment_token,
                            jira_headers_attachment,
                            ssl_config,
                            proxy_dict,
                            timeout,
                        )

                    elif jira_attachment in ("enabled_json"):
                        attach_json(
                            helper,
                            jira_root_url,
                            jira_backlog_key,
                            jira_attachment_token,
                            jira_headers_attachment,
                            ssl_config,
                            proxy_dict,
                            timeout,
                        )

                    elif jira_attachment in ("enabled_xlsx"):
                        attach_xlsx(
                            helper,
                            jira_root_url,
                            jira_backlog_key,
                            jira_attachment_token,
                            jira_headers_attachment,
                            ssl_config,
                            proxy_dict,
                            timeout,
                        )

                else:
                    helper.log_info(
                        f"JIRA Service Desk ticket successfully created. {jira_url},"
                        f" content={response.text}"
                    )
                    jira_creation_response = response.text

                    # Store the sha256 hash of the JIRA issue in the backlog KVstore with the key values returned by JIRA
                    jira_creation_response_json = json.loads(jira_creation_response)
                    jira_created_id = jira_creation_response_json["id"]
                    jira_created_key = jira_creation_response_json["key"]
                    jira_created_self = jira_creation_response_json["self"]
                    helper.log_debug(
                        f"jira_creation_response_json:={jira_creation_response_json}"
                    )

                    # Check for auto-closure on the newly created issue
                    perform_auto_closure(
                        helper,
                        jira_url,
                        jira_headers,
                        ssl_config,
                        proxy_dict,
                        timeout,
                        event,
                        jira_auto_close,
                        jira_auto_close_key_value_pair,
                        jira_auto_close_status_transition_value,
                        jira_auto_close_issue_number_field_name,
                        jira_auto_close_status_transition_comment,
                        jira_created_key,
                    )

                    record_url = (
                        f"{splunkd_uri}/servicesNS/nobody/"
                        "TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_issues_backlog"
                    )
                    headers = {
                        "Authorization": "Splunk %s" % session_key,
                        "Content-Type": "application/json",
                    }

                    if jira_dedup_sha256_found:
                        record = {
                            "account": str(account),
                            "jira_sha256": jira_sha256sum,
                            "ctime": time.time(),
                            "mtime": time.time(),
                            "status": "created",
                            "jira_id": jira_created_id,
                            "jira_key": jira_created_key,
                            "jira_self": jira_created_self,
                        }
                        record = json.dumps(record).encode("utf-8")
                        helper.log_debug(f"record={record}")
                    else:
                        record = {
                            "account": str(account),
                            "_key": jira_sha256sum,
                            "jira_sha256": jira_sha256sum,
                            "ctime": time.time(),
                            "mtime": time.time(),
                            "status": "created",
                            "jira_id": jira_created_id,
                            "jira_key": jira_created_key,
                            "jira_self": jira_created_self,
                        }
                        record = json.dumps(record).encode("utf-8")
                        helper.log_debug(f"record={record}")

                    response = requests.post(
                        record_url, headers=headers, data=record, verify=False
                    )
                    if response.status_code not in (200, 201, 204):
                        helper.log_error(
                            f"Backlog KVstore saving has failed!. url={record_url}, data={record}, HTTP Error={response.status_code}, "
                            f"content={response.text}"
                        )
                    else:
                        helper.log_debug(
                            f"JIRA issue successfully added to the backlog collection. "
                            f"content={response.text}"
                        )

                    # Manage attachment
                    if jira_attachment in ("enabled_csv"):
                        attach_csv(
                            helper,
                            jira_root_url,
                            jira_created_key,
                            jira_attachment_token,
                            jira_headers_attachment,
                            ssl_config,
                            proxy_dict,
                            timeout,
                        )

                    elif jira_attachment in ("enabled_json"):
                        attach_json(
                            helper,
                            jira_root_url,
                            jira_created_key,
                            jira_attachment_token,
                            jira_headers_attachment,
                            ssl_config,
                            proxy_dict,
                            timeout,
                        )

                    elif jira_attachment in ("enabled_xlsx"):
                        attach_xlsx(
                            helper,
                            jira_root_url,
                            jira_created_key,
                            jira_attachment_token,
                            jira_headers_attachment,
                            ssl_config,
                            proxy_dict,
                            timeout,
                        )

                # Return the JIRA response as final word
                return jira_creation_response


def perform_auto_closure(
    helper,
    jira_url,
    jira_headers,
    ssl_config,
    proxy_dict,
    timeout,
    event,
    jira_auto_close,
    jira_auto_close_key_value_pair,
    jira_auto_close_status_transition_value,
    jira_auto_close_issue_number_field_name,
    jira_auto_close_status_transition_comment,
    jira_backlog_key=None,
):
    """
    Perform auto-closure of a Jira issue based on the provided parameters and event data.

    Args:
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
