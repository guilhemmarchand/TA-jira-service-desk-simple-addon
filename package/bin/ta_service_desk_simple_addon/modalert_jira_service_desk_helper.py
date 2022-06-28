# encoding = utf-8

# This function can optionnally be used to only remove the espaced double quotes and leave the custom fields with no parsing at all
def reformat_customfields_minimal(i):

    import re

    if i is not None:
        i = re.sub(r'\\"', '"', i)
        i = re.sub(r'},$', '}', i)

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
    helper.log_debug("auth_type={}".format(auth_type))

    # Get username
    username = account_details.get("username", 0)
    helper.log_debug("username={}".format(username))
    # by convention
    jira_username = username

    # Get passowrd
    password = account_details.get("password", 0)
    # helper.log_info("password={}".format(password))
    # by convention
    jira_password = password

    # Get authentication mode
    jira_auth_mode = account_details.get("jira_auth_mode", 0)
    helper.log_debug("jira_auth_mode={}".format(jira_auth_mode))

    # Get jira_url
    jira_url = account_details.get("jira_url", 0)
    helper.log_debug("jira_url={}".format(jira_url))

    # Get jira_ssl_certificate_validation
    jira_ssl_certificate_validation = int(account_details.get("jira_ssl_certificate_validation", 0))
    helper.log_debug("jira_ssl_certificate_validation={}".format(jira_ssl_certificate_validation))
    ssl_certificate_validation = True
    if jira_ssl_certificate_validation == 0:
        ssl_certificate_validation = False
    helper.log_debug("ssl_certificate_validation={}".format(ssl_certificate_validation))

    # Get jira_ssl_certificate_path
    # SSL certificate path - customers using an internal PKI can use this option to verify the certificate bundle
    # See: https://docs.python-requests.org/en/stable/user/advanced/#ssl-cert-verification
    # If it is set, and the SSL verification is enabled, and the file exists, the file path replaces the boolean in the requests calls    
    jira_ssl_certificate_path = account_details.get("jira_ssl_certificate_path", 0)
    helper.log_debug("jira_ssl_certificate_path={}".format(jira_ssl_certificate_path))
    if jira_ssl_certificate_path not in ["", "None", None]:
        helper.log_debug("jira_ssl_certificate_path={}".format(jira_ssl_certificate_path))
        # replace the ssl_certificate_validation boolean by the SSL certiticate path if the file exists
        import os
        if ssl_certificate_validation and jira_ssl_certificate_path:
            if os.path.isfile(jira_ssl_certificate_path):
                ssl_certificate_validation = str(jira_ssl_certificate_path)

    # Get Passthrough mode
    jira_passthrough_mode = helper.get_global_setting("jira_passthrough_mode")
    helper.log_debug("jira_passthrough_mode={}".format(jira_passthrough_mode))
    # if an alert was created before this setting was introduced
    if jira_passthrough_mode in ["", "None", None]:
        jira_passthrough_mode = 0
    else:
        jira_passthrough_mode = int(jira_passthrough_mode)
    # False by default
    passthrough_mode = False
    helper.log_debug("jira_passthrough_mode={}".format(jira_passthrough_mode))
    if jira_passthrough_mode == 1:
        passthrough_mode = True
        helper.log_info("passthrough_mode: Jira passthrough mode is enabled, this instance will not attempt to contact Jira, issues will be written to the replay KVstore.")
    helper.log_debug("passthrough_mode={}".format(passthrough_mode))

    #call the query URL REST Endpoint and pass the url and API token
    content = query_url(helper, account, jira_auth_mode, jira_url, jira_username, jira_password, ssl_certificate_validation, passthrough_mode)  

    return 0


# simple def to return current time for file naming
def get_timestr():

    from time import localtime, strftime
    timestr = strftime("%Y-%m-%d-%H%M%S", localtime())

    return timestr

def get_tempdir():

    import os
    import re
    import platform

    # If running Windows OS (used for directory identification)
    is_windows = re.match(r'^win\w+', (platform.system().lower()))

    # SPLUNK_HOME environment variable
    SPLUNK_HOME = os.environ['SPLUNK_HOME']

    # define the directory for temp files
    if is_windows:
        tempdir = SPLUNK_HOME + '\\etc\\apps\\TA-jira-service-desk-simple-addon\\tmp'
    else:
        tempdir = SPLUNK_HOME + '/etc/apps/TA-jira-service-desk-simple-addon/tmp'
    if not os.path.exists(tempdir):
        os.mkdir(tempdir)

    return tempdir


# This function is made necessary due to Windows incapability to purge temporary files properly, as other serious OS would
def clean_tempdir():

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
        for xfile in glob.glob('*'):
            filemtime = os.path.getmtime(xfile)
            if time.time() - filemtime > 300:
                try:
                    os.remove(xfile)
                except Exception as e:
                    helper.log_debug('Temporary file ' + str(xfile) + ' could not be removed, we will try another chance later on')


def attach_csv(helper, jira_url, jira_created_key, jira_attachment_token, jira_headers_attachment, ssl_certificate_validation, proxy_dict, *args, **kwargs):

    import gzip
    import tempfile
    import requests
    import os

    # Get tempdir
    tempdir = get_tempdir()

    # Clean tempdir
    clean_tempdir()

    timestr = get_timestr()
    results_csv = tempfile.NamedTemporaryFile(mode='w+t', prefix="splunk_alert_results_" + str(timestr) + "_", suffix='.csv', dir=tempdir, delete=False)
    jira_url = jira_url + "/" + jira_created_key + "/attachments"

    input_file = gzip.open(jira_attachment_token, 'rt')
    all_data = input_file.read()
    results_csv.writelines(str(all_data))
    results_csv.seek(0)

    try:

        files = {'file': open(results_csv.name, 'rb')}
        response = requests.post(jira_url, files=files, headers=jira_headers_attachment,
                                verify=ssl_certificate_validation, proxies=proxy_dict)
        helper.log_debug("response status_code:={}".format(response.status_code))

        if response.status_code not in (200, 201, 204):
            helper.log_error(
                'JIRA Service Desk ticket attachment file upload has failed!. url={}, '
                'jira_attachment_token={}, HTTP Error={}, '
                'content={}'.format(jira_url, jira_attachment_token, response.status_code,
                                    response.text))
        else:
            helper.log_info('JIRA Service Desk ticket attachment file uploaded successfully. {},'
                        ' content={}'.format(jira_url, response.text))

    # any exception such as proxy error, dns failure etc. will be catch here
    except Exception as e:
        helper.log_error("JIRA Service Desk ticket attachment file "
                        "upload has failed!:{}".format(str(e)))

    finally:
        results_csv.close()

        # try clean
        try:
            if os.path.isfile(results_csv.name):
                os.remove(results_csv.name)
        except Exception as e:
            helper.log_debug('Temporary file ' + str(results_csv.name) + ' could not be removed, unfortunately this is expected under Windows host guests')

def attach_json(helper, jira_url, jira_created_key, jira_attachment_token, jira_headers_attachment, ssl_certificate_validation, proxy_dict, *args, **kwargs):

    import gzip
    import tempfile
    import csv
    import json
    import requests
    import os

    # Get tempdir
    tempdir = get_tempdir()

    # Clean tempdir
    clean_tempdir()

    timestr = get_timestr()
    results_csv = tempfile.NamedTemporaryFile(mode='w+t', prefix="splunk_alert_results_" + str(timestr) + "_",
                                            suffix='.csv', dir=tempdir, delete=False)
    results_json = tempfile.NamedTemporaryFile(mode='w+t', prefix="splunk_alert_results_" + str(timestr) + "_",
                                            suffix='.json', dir=tempdir, delete=False)
    jira_url = jira_url + "/" + jira_created_key + "/attachments"

    input_file = gzip.open(jira_attachment_token, 'rt')
    all_data = input_file.read()
    results_csv.writelines(str(all_data))
    results_csv.seek(0)

    # Convert CSV to JSON
    reader = csv.DictReader(open(results_csv.name))
    results_json.writelines(str(json.dumps([row for row in reader], indent=2)))
    results_json.seek(0)

    try:

        files = {'file': open(results_json.name, 'rb')}
        response = requests.post(jira_url, files=files, headers=jira_headers_attachment,
                                verify=ssl_certificate_validation, proxies=proxy_dict)

        helper.log_debug("response status_code:={}".format(response.status_code))

        if response.status_code not in (200, 201, 204):
            helper.log_error(
                'JIRA Service Desk ticket attachment file upload has failed!. url={}, '
                'jira_attachment_token={}, HTTP Error={}, '
                'content={}'.format(jira_url, jira_attachment_token, response.status_code,
                                    response.text))
        else:
            helper.log_info('JIRA Service Desk ticket attachment file uploaded successfully. {},'
                        ' content={}'.format(jira_url, response.text))

    # any exception such as proxy error, dns failure etc. will be catch here
    except Exception as e:
        helper.log_error("JIRA Service Desk ticket attachment file upload "
                        "has failed!:{}".format(str(e)))

    finally:
        results_csv.close()
        results_json.close()

        # try clean
        try:
            if os.path.isfile(results_csv.name):
                os.remove(results_csv.name)
        except Exception as e:
            helper.log_debug('Temporary file ' + str(results_csv.name) + 'could not be removed, unfortunately this is expected under Windows host guests')

        # try clean
        try:
            if os.path.isfile(results_json.name):
                os.remove(results_json.name)
        except Exception as e:
            helper.log_debug('Temporary file ' + str(results_json.name) + ' could not be removed, unfortunately this is expected under Windows host guests')


def attach_xlsx(helper, jira_url, jira_created_key, jira_attachment_token, jira_headers_attachment, ssl_certificate_validation, proxy_dict, *args, **kwargs):

    import gzip
    import tempfile
    import requests
    import csv
    import openpyxl
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
    import os

    # Get tempdir
    tempdir = get_tempdir()

    # Clean tempdir
    clean_tempdir()

    timestr = get_timestr()
    results_csv = tempfile.NamedTemporaryFile(mode='w+t', prefix="splunk_alert_results_" + str(timestr) + "_", suffix='.csv', dir=tempdir, delete=False)
    results_xlsx = tempfile.NamedTemporaryFile(mode='w+t', prefix="splunk_alert_results_" + str(timestr) + "_", suffix='.xlsx', dir=tempdir, delete=False)
    jira_url = jira_url + "/" + jira_created_key + "/attachments"

    input_file = gzip.open(jira_attachment_token, 'rt')
    all_data = input_file.read()
    results_csv.writelines(str(all_data))
    results_csv.seek(0)
    
    # convert csv to xlsx
    wb = openpyxl.Workbook()
    ws = wb.active

    reader = csv.reader(open(results_csv.name), delimiter=',')
    count = 0
    for row in reader:
        count+=1
        if count ==1:
            # to allow column names starting with _
            ws.append([ILLEGAL_CHARACTERS_RE.sub('', _i) for _i in row])
        else:
            ws.append(row)

    wb.save(results_xlsx.name)
    results_xlsx.seek(0)

    try:

        files = {'file': open(results_xlsx.name, 'rb')}
        response = requests.post(jira_url, files=files, headers=jira_headers_attachment,
                                verify=ssl_certificate_validation, proxies=proxy_dict)
        helper.log_debug("response status_code:={}".format(response.status_code))

        if response.status_code not in (200, 201, 204):
            helper.log_error(
                'JIRA Service Desk ticket attachment file upload has failed!. url={}, '
                'jira_attachment_token={}, HTTP Error={}, '
                'content={}'.format(jira_url, jira_attachment_token, response.status_code,
                                    response.text))
        else:
            helper.log_info('JIRA Service Desk ticket attachment file uploaded successfully. {},'
                        ' content={}'.format(jira_url, response.text))

    # any exception such as proxy error, dns failure etc. will be catch here
    except Exception as e:
        helper.log_error("JIRA Service Desk ticket attachment file "
                        "upload has failed!:{}".format(str(e)))

    finally:
        results_csv.close()
        results_xlsx.close()

        # try clean
        try:
            if os.path.isfile(results_csv.name):
                os.remove(results_csv.name)
        except Exception as e:
            helper.log_debug('Temporary file ' + str(results_csv.name) + ' could not be removed, unfortunately this is expected under Windows host guests')

        # try clean
        try:
            if os.path.isfile(results_xlsx.name):
                os.remove(results_xlsx.name)
        except Exception as e:
            helper.log_debug('Temporary file ' + str(results_xlsx.name) + ' could not be removed, unfortunately this is expected under Windows host guests')


def query_url(helper, account, jira_auth_mode, jira_url, jira_username, jira_password, ssl_certificate_validation, passthrough_mode):

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
    helper.log_debug("Get session_key.")
    session_key = helper.session_key

    # Get splunkd port
    entity = splunk.entity.getEntity('/server', 'settings',
                                     namespace='TA-jira-service-desk-simple-addon', sessionKey=session_key, owner='-')
    mydict = entity
    splunkd_port = mydict['mgmtHostPort']
    helper.log_debug("splunkd_port={}".format(splunkd_port))

    service = client.connect(
        owner="nobody",
        app="TA-jira-service-desk-simple-addon",
        port=splunkd_port,
        token=session_key
    )
    storage_passwords = service.storage_passwords

    # For Splunk Cloud vetting, the URL must start with https://
    if not jira_url.startswith("https://"):
        jira_url = 'https://' + jira_url + '/rest/api/latest/issue'
    else:
        jira_url = jira_url + '/rest/api/latest/issue'
    # keep this url as a super url
    jira_root_url = jira_url

    # get proxy configuration
    # note: the proxy dict is used with requests calls when attachment is enabled
    proxy_config = helper.get_proxy()
    proxy_enabled = "0"
    proxy_url = proxy_config.get("proxy_url")
    proxy_dict = None
    proxy_username = None
    helper.log_debug("proxy_url={}".format(proxy_url))

    if proxy_url is not None:
        opt_use_proxy = True
        helper.log_debug("use_proxy set to True")

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
        helper.log_debug("use_proxy set to False")

    # Retrieve parameters which are not event related
    jira_project = helper.get_param("jira_project")
    helper.log_debug("jira_project={}".format(jira_project))

    jira_issue_type = helper.get_param("jira_issue_type")
    helper.log_debug("jira_issue_type={}".format(jira_issue_type))

    jira_priority = helper.get_param("jira_priority")
    helper.log_debug("jira_priority={}".format(jira_priority))

    jira_dedup_enabled = False
    jira_dedup = helper.get_param("jira_dedup")
    if jira_dedup == 'enabled':
        jira_dedup_enabled = True
    helper.log_debug("jira_dedup_enabled={}".format(jira_dedup_enabled))

    jira_dedup_exclude_statuses = helper.get_param("jira_dedup_exclude_statuses")
    if jira_dedup_exclude_statuses in ["", "None", None]:
        jira_dedup_exclude_statuses = "Done"
    helper.log_debug("jira_dedup_exclude_statuses={}".format(jira_dedup_exclude_statuses))
    # needs to be converted to an array for later processing
    jira_dedup_exclude_statuses = jira_dedup_exclude_statuses.split(",")

    jira_dedup_content = helper.get_param("jira_dedup_content")
    if jira_dedup_content in ["", "None", None]:
        jira_dedup_full_mode = True
        helper.log_debug("jira_dedup: jira_dedup_full_mode is set to True, the full issue data will be used"
                        " for the md5 calculation.")
    else:
        jira_dedup_full_mode = False
        helper.log_debug("jira_dedup: jira_dedup_full_mode is set to False, the md5 calculation scope will be restricted"
                         " to the content of the jira_dedup_content.")
        helper.log_debug("jira_dedup_content={}".format(jira_dedup_content))

    jira_attachment = helper.get_param("jira_attachment")
    helper.log_debug("jira_attachment={}".format(jira_attachment))

    if jira_attachment in ["", "None", None]:
        jira_attachment = "disabled"
    helper.log_debug("jira_attachment:={}".format(jira_attachment))

    jira_attachment_token = helper.get_param("jira_attachment_token")
    helper.log_debug("jira_attachment_token={}".format(jira_attachment_token))

    jira_customfields_parsing = helper.get_param("jira_customfields_parsing")
    helper.log_debug("jira_customfields_parsing={}".format(jira_customfields_parsing))

    if jira_customfields_parsing in ["", "None", None]:
        jira_customfields_parsing = "enabled"
    helper.log_debug("jira_customfields_parsing:={}".format(jira_customfields_parsing))

    # Build the authentication header for JIRA
    if str(jira_auth_mode) == 'basic':
        authorization = jira_username + ':' + jira_password
        b64_auth = base64.b64encode(authorization.encode()).decode()
        jira_headers = {
            'Authorization': 'Basic %s' % b64_auth,
            'Content-Type': 'application/json',
        }
        # required when uploading attachments
        jira_headers_attachment = {
            'Authorization': 'Basic %s' % b64_auth,
            'X-Atlassian-Token': 'no-check'
        }
    elif str(jira_auth_mode) == 'pat':
        jira_headers = {
            'Authorization': 'Bearer %s' % str(jira_password),
            'Content-Type': 'application/json',
        }
        # required when uploading attachments
        jira_headers_attachment = {
            'Authorization': 'Bearer %s' % str(jira_password),
            'X-Atlassian-Token': 'no-check'
        }

    # Loop within events and proceed
    events = helper.get_events()
    for event in events:
        helper.log_debug("event={}".format(event))

        jira_priority_dynamic = helper.get_param("jira_priority_dynamic")
        helper.log_debug("jira_priority_dynamic={}".format(jira_priority_dynamic))

        jira_summary = helper.get_param("jira_summary")
        helper.log_debug("jira_summary={}".format(jira_summary))

        jira_description = helper.get_param("jira_description")
        helper.log_debug("jira_description={}".format(jira_description))

        jira_assignee = helper.get_param("jira_assignee")
        helper.log_debug("jira_assignee={}".format(jira_assignee))

        jira_reporter = helper.get_param("jira_reporter")
        helper.log_debug("jira_reporter={}".format(jira_reporter))

        jira_labels = helper.get_param("jira_labels")
        helper.log_debug("jira_labels={}".format(jira_labels))

        jira_components = helper.get_param("jira_components")
        helper.log_debug("jira_components={}".format(jira_components))

        # Retrieve the custom fields
        jira_customfields = helper.get_param("jira_customfields")
        helper.log_debug("jira_customfields={}".format(jira_customfields))

        # Manage custom fields properly

        data = {}

        # add project
        data['fields'] = { 'project': { 'key' : jira_project } }

        # add summary
        data['fields']['summary'] = jira_summary

        # add description
        data['fields']['description'] = jira_description

        # add issue type
        data['fields']['issuetype'] = { 'name': jira_issue_type }

        # JIRA assignee
        if jira_assignee not in ["", "None", None]:
            # add assignee
            data['fields']['assignee'] = { 'accountId': jira_assignee }

        # JIRA reporter
        if jira_reporter not in ["", "None", None]:
            data['fields']['reporter'] = { 'accountId': jira_reporter }

        # Priority can be dynamically overridden by the text input dynamic priority, if set
        if jira_priority not in ["", "None", None]:
            if jira_priority_dynamic not in ["", "None", None]:
                helper.log_debug("jira priority is overridden by "
                                 "jira_priority_dynamic={}".format(jira_priority_dynamic))
                # add
                data['fields']['priority'] = { 'name': jira_priority_dynamic }

            else:
                # add
                data['fields']['priority'] = { 'name': jira_priority }

        # labels
        if jira_labels not in ["", "None", None]:
            data['fields']['labels'] = jira_labels.split(",")

        # components
        if jira_components not in ["", "None", None]:
            data['fields']['components'] = jira_components.split(",")

        # JIRA custom fields structure
        if jira_customfields not in ["", "None", None]:
            helper.log_debug("After format, jira_customfields=\"{}\"".format(reformat_customfields_minimal(jira_customfields)))
            jira_customfields = "{" + reformat_customfields_minimal(jira_customfields) + "}"
            try:
                jira_customfields_json = json.loads(jira_customfields)

                # Loop
                for jira_customfields_sub in jira_customfields_json:
                    data['fields'][jira_customfields_sub] = jira_customfields_json[jira_customfields_sub]

            except Exception as e:
                helper.log_error("Failed to load jira_customfields=\"{}\" as a proper formated JSON object with exception=\"{}\"".format(jira_customfields, e))

        # log raw json in debug mode
        helper.log_debug("JSON payload before submission=\"{}\"".format(json.dumps(data)))
        helper.log_debug("JSON pretty print before submission=\"{}\"".format(json.dumps(data, indent=4)))

        # Generate an md5 unique hash for this issue
        # If jira_dedup_full_mode is set to True, the entire json data is used
        # Otherwise, jira_dedup_content was detected as filled and its content is used to perform the md5 calculation
        if jira_dedup_full_mode:
            jira_md5sum = hashlib.md5(json.dumps(data).encode())
        else:
            jira_md5sum = hashlib.md5(jira_dedup_content.encode())
        jira_md5sum = jira_md5sum.hexdigest()
        helper.log_debug("jira_md5sum:={}".format(jira_md5sum))

        # Initiate default behaviour
        jira_dedup_md5_found = False
        jira_dedup_comment_issue = False

        # Verify the collection, if the collection returns a result for this md5 as the _key, this issue
        # is a duplicate (http 200)
        record_url = 'https://localhost:' + str(splunkd_port) \
                     + '/servicesNS/nobody/' \
                       'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_issues_backlog/' \
                     + str(jira_md5sum)
        headers = {
            'Authorization': 'Splunk %s' % session_key,
            'Content-Type': 'application/json'}

        response = requests.get(record_url, headers=headers, verify=False)
        helper.log_debug("response status_code:={}".format(response.status_code))

        if response.status_code == 200:
            if jira_dedup_enabled:
                helper.log_info(
                    'jira_dedup: An issue with same md5 hash (' + str(jira_md5sum) + ') was found in the backlog '
                    'collection, as jira_dedup is enabled a new comment '
                    'will be added if the issue is active. (status is not resolved or any other done status), entry:={}'.format(response.text))
                jira_backlog_response = response.text
                jira_backlog_response_json = json.loads(jira_backlog_response)
                helper.log_debug("jira_backlog_response_json:={}".format(jira_backlog_response_json))

                jira_backlog_id = jira_backlog_response_json['jira_id']
                jira_backlog_key = jira_backlog_response_json['jira_key']
                jira_backlog_kvkey = jira_backlog_response_json['_key']
                jira_backlog_self = jira_backlog_response_json['jira_self']
                jira_backlog_md5 = jira_backlog_response_json['jira_md5']
                jira_backlog_ctime = jira_backlog_response_json['ctime']

                helper.log_debug("jira_backlog_key:={}".format(jira_backlog_key))

                # Attempt to get the current status of the issue
                # Define status url on top of jira_url

                # Define first the status to unknown, if the status is Closed a new issue will be created
                # if dedup is enabled
                jira_issue_status = 'Unknown'
                jira_issue_status_category = 'Unknown'
                jira_url_status = jira_url + '/' + str(jira_backlog_key)
                helper.log_debug("jira_url_status:={}".format(jira_url_status))

                # Try http get, catch exceptions and incorrect http return codes
                try:
                    response = helper.send_http_request(jira_url_status, "GET", parameters=None, payload=data,
                                                        headers=jira_headers, cookies=None,
                                                        verify=ssl_certificate_validation,
                                                        cert=None, timeout=120, use_proxy=opt_use_proxy)
                    helper.log_debug("response status_code:={}".format(response.status_code))

                    # No http exception, but http post was not successful
                    if response.status_code not in (200, 201, 204):
                        helper.log_error(
                            'JIRA Service Desk get ticket status has failed!. url={}, data={}, HTTP Error={}, '
                            'content={}'.format(jira_url_status, data, response.status_code, response.text))

                    else:

                        jira_get_response = response.text
                        jira_get_response_json = json.loads(jira_get_response)
                        jira_issue_status = jira_get_response_json['fields']['status']['name']
                        jira_issue_status_category = jira_get_response_json['fields']['status']['statusCategory']['name']
                        helper.log_debug("jira_issue_status:={}".format(jira_issue_status))
                        helper.log_debug("jira_issue_status_category:={}".format(jira_issue_status_category))

                # any exception such as proxy error, dns failure etc. will be catch here
                except Exception as e:
                    helper.log_error("JIRA Service Desk get ticket status has failed!:{}".format(str(e)))
                    helper.log_error(
                        'message content={}'.format(data))
                    jira_issue_status = 'Unknown'

                # If dedup is enabled and the issue status is not closed
                if jira_dedup_enabled and jira_issue_status_category not in jira_dedup_exclude_statuses:
                    
                    # Log a message
                    helper.log_info(
                    'jira_dedup: The issue with key ' + str(jira_backlog_key) + ' was set to status: \"'
                    + jira_issue_status + '\" (status category: \"' + jira_issue_status_category + '\"), '
                    'therefore, a new comment will be added to this issue.')
                    
                    # generate a new jira_url, and the comment
                    jira_dedup_comment_issue = True
                    jira_url = jira_url + "/" + str(jira_backlog_key) + "/comment"
                    helper.log_debug("jira_url:={}".format(jira_url))

                    # Handle the JIRA comment to be added, if a field named jira_update_comment is part of the result,
                    # its content will used for the comment content.
                    jira_update_comment = { 'body': 'New alert triggered: ' + jira_summary }
                    
                    for key, value in event.items():
                        if key in "jira_update_comment":
                            jira_update_comment = { 'body': value }

                    helper.log_debug("jira_update_comment:={}".format(jira_update_comment))

                    data = jira_update_comment

                    helper.log_debug("JSON payload before submission={}".format(json.dumps(jira_update_comment)))

                # dedup is enabled but the issue was resolved, closed or cancelled
                elif jira_dedup_enabled and jira_issue_status_category in jira_dedup_exclude_statuses:
                    helper.log_info(
                    'jira_dedup: The issue with key ' + str(jira_backlog_key) + ' has the same MD5 hash: '
                    + jira_backlog_md5
                    + ' and its status was set to: \"' + jira_issue_status + '\" (status category: \"' + jira_issue_status_category +
                    '\"), a new comment will not be added to an issue in this status, therefore a new issue '
                                                                          'will be created.')

                    # Remove this issue from the backlog collection
                    record_url = 'https://localhost:' + str(splunkd_port) \
                                + '/servicesNS/nobody/' \
                                'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_issues_backlog'
                    headers = {
                        'Authorization': 'Splunk %s' % session_key,
                        'Content-Type': 'application/json'}

                    response = requests.delete(record_url + '/' + jira_md5sum, headers=headers, verify=False)

                    if response.status_code not in (200, 201, 204):
                        helper.log_error(
                            'KVstore saving has failed!. url={}, data={}, HTTP Error={}, '
                            'content={}'.format(record_url, record, response.status_code, response.text))
                    else:
                        helper.log_debug('JIRA issue record in the backlog collection was successfully delete. '
                                    'content={}'.format(response.text))

                    jira_dedup_md5_found = False

            else:
                helper.log_info(
                    'jira_dedup: An issue with same md5 hash (' + str(jira_md5sum) + ') was found in the backlog '
                    'collection, as jira_dedup is not enabled a new issue '
                    'will be created, entry:={}'.format(response.text))
                jira_dedup_md5_found = True

        else:
            helper.log_debug(
                'jira_dedup: The calculated md5 hash for this issue creation request (' + str(jira_md5sum) +
                ') was not found in the backlog collection, a new issue will be created')
            jira_dedup_md5_found = False

        # Try http post, catch exceptions and incorrect http return codes

        #
        # passthrough_mode: in this mode, the instance will not perform a real call to JIRA
        # Instead, it will use the replay KVstore and will store the json data of the REST call to be performed
        # This mode is designed to accomodate use cases such as Splunk Cloud where the Cloud instance cannot contact an on-premise JIRA deployment
        # A second search head running on-premise would recycle the replay KVstore results and perform the true call to JIRA
        #

        if passthrough_mode:

            # For issue creation only
            if not jira_dedup_comment_issue:

                # Store the failed publication in the replay KVstore
                record_url = 'https://localhost:' + str(
                    splunkd_port) + '/servicesNS/nobody/' \
                                    'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay'
                record_uuid = str(uuid.uuid1())
                headers = {
                    'Authorization': 'Splunk %s' % session_key,
                    'Content-Type': 'application/json'}

                record = {
                    'account': str(account),
                    '_key': record_uuid,
                    'ctime': str(time.time()),
                    'status': 'pending',
                    'no_attempts': 0,
                    'data': data,
                }

                response = requests.post(record_url, headers=headers, data=json.dumps(record),
                                         verify=False)
                if response.status_code not in (200, 201, 204):
                    helper.log_error(
                        'KVstore saving has failed!. url={}, data={}, HTTP Error={}, '
                        'content={}'.format(record_url, record, response.status_code, response.text))
                else:
                    helper.log_info('JIRA Service Desk is running in passthrough mode, the ticket data was stored in the '
                                    'replay KVstore with uuid: ' + record_uuid)                    

        else:


            try:
                response = helper.send_http_request(jira_url, "POST", parameters=None, payload=data,
                                                    headers=jira_headers, cookies=None, verify=ssl_certificate_validation,
                                                    cert=None, timeout=120, use_proxy=opt_use_proxy)
                helper.log_debug("response status_code:={}".format(response.status_code))

                # No http exception, but http post was not successful
                if response.status_code not in (200, 201, 204):
                    helper.log_error(
                        'JIRA Service Desk ticket creation has failed!. url={}, data={}, HTTP Error={}, '
                        'content={}'.format(jira_url, data, response.status_code, response.text))

                    # For issue creation only
                    if not jira_dedup_comment_issue:
                        record_url = 'https://localhost:' + str(splunkd_port) \
                                    + '/servicesNS/nobody/' \
                                    'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_failures_replay'
                        record_uuid = str(uuid.uuid1())
                        helper.log_error('JIRA Service Desk failed ticket stored for next chance replay purposes in the '
                                        'replay KVstore with uuid: ' + record_uuid)
                        headers = {
                            'Authorization': 'Splunk %s' % session_key,
                            'Content-Type': 'application/json'}

                        record = {
                            'account': str(account),
                            '_key': record_uuid,
                            'ctime': str(time.time()),
                            'status': 'temporary_failure',
                            'no_attempts': 1,
                            'data': data
                        }

                        response = requests.post(record_url, headers=headers, data=json.dumps(record),
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

                # For issue creation only
                if not jira_dedup_comment_issue:

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

                    record = {
                        'account': str(account),
                        '_key': record_uuid,
                        'ctime': str(time.time()),
                        'status': 'temporary_failure',
                        'no_attempts': 1,
                        'data': data,
                    }

                    response = requests.post(record_url, headers=headers, data=json.dumps(record),
                                            verify=False)
                    if response.status_code not in (200, 201, 204):
                        helper.log_error(
                            'KVstore saving has failed!. url={}, data={}, HTTP Error={}, '
                            'content={}'.format(record_url, record, response.status_code, response.text))

                return 0

            else:
                if jira_dedup_comment_issue:
                    helper.log_info('JIRA Service Desk ticket successfully updated. {},'
                                    ' content={}'.format(jira_url, response.text))
                    jira_creation_response = response.text

                    # Update the backlog collection entry
                    record_url = 'https://localhost:' + str(splunkd_port) \
                                + '/servicesNS/nobody/' \
                                'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_issues_backlog/' \
                                + jira_backlog_kvkey
                    headers = {
                        'Authorization': 'Splunk %s' % session_key,
                        'Content-Type': 'application/json'}

                    record = '{"account": "' + str(account) + '", "jira_md5": "' + jira_backlog_md5 + '", "ctime": "' + jira_backlog_ctime + '", "mtime": "' \
                            + str(time.time()) + '", "status": "updated", "jira_id": "' \
                            + jira_backlog_id + '", "jira_key": "' \
                            + jira_backlog_key + '", "jira_self": "' + jira_backlog_self + '"}'
                    helper.log_debug('record={}'.format(record))

                    response = requests.post(record_url, headers=headers, data=record,
                                            verify=False)
                    if response.status_code not in (200, 201, 204):
                        helper.log_error(
                            'Backlog KVstore saving has failed!. url={}, data={}, HTTP Error={}, '
                            'content={}'.format(record_url, record, response.status_code, response.text))
                    else:
                        helper.log_debug('JIRA issue record in the backlog collection was successfully updated. '
                                        'content={}'.format(response.text))

                    # Manage attachment
                    if jira_attachment in ("enabled_csv"):
                        attach_csv(helper, jira_root_url, jira_backlog_key, jira_attachment_token, jira_headers_attachment, ssl_certificate_validation, proxy_dict)

                    elif jira_attachment in ("enabled_json"):
                        attach_json(helper, jira_root_url, jira_backlog_key, jira_attachment_token, jira_headers_attachment, ssl_certificate_validation, proxy_dict)

                    elif jira_attachment in ("enabled_xlsx"):
                        attach_xlsx(helper, jira_root_url, jira_backlog_key, jira_attachment_token, jira_headers_attachment, ssl_certificate_validation, proxy_dict)

                else:
                    helper.log_info('JIRA Service Desk ticket successfully created. {},'
                                    ' content={}'.format(jira_url, response.text))
                    jira_creation_response = response.text

                    # Store the md5 hash of the JIRA issue in the backlog KVstore with the key values returned by JIRA
                    jira_creation_response_json = json.loads(jira_creation_response)
                    jira_created_id = jira_creation_response_json['id']
                    jira_created_key = jira_creation_response_json['key']
                    jira_created_self = jira_creation_response_json['self']
                    helper.log_debug("jira_creation_response_json:={}".format(jira_creation_response_json))

                    record_url = 'https://localhost:' + str(splunkd_port) \
                                + '/servicesNS/nobody/' \
                                'TA-jira-service-desk-simple-addon/storage/collections/data/kv_jira_issues_backlog'
                    headers = {
                        'Authorization': 'Splunk %s' % session_key,
                        'Content-Type': 'application/json'}

                    if jira_dedup_md5_found:
                        record = '{"account": "' + str(account) + '", "jira_md5": "' + jira_md5sum + '", "ctime": "' \
                                + str(time.time()) + '", "mtime": "' \
                                + str(time.time()) + '", "status": "created", "jira_id": "' \
                                + jira_created_id + '", "jira_key": "' \
                                + jira_created_key + '", "jira_self": "' + jira_created_self + '"}'
                        # Force encode UTF8
                        record = record.encode('utf-8')
                        helper.log_debug('record={}'.format(record))
                    else:
                        record = '{"account": "' + str(account) + '", "_key": "' + jira_md5sum + '", "jira_md5": "' + jira_md5sum + '", "ctime": "' \
                                + str(time.time()) + '", "mtime": "' + str(time.time()) \
                                + '", "status": "created", "jira_id": "' + jira_created_id \
                                + '", "jira_key": "' + jira_created_key + '", "jira_self": "' + jira_created_self + '"}'
                        # Force encode UTF8
                        record = record.encode('utf-8')
                        helper.log_debug('record={}'.format(record))

                    response = requests.post(record_url, headers=headers, data=record,
                                            verify=False)
                    if response.status_code not in (200, 201, 204):
                        helper.log_error(
                            'Backlog KVstore saving has failed!. url={}, data={}, HTTP Error={}, '
                            'content={}'.format(record_url, record, response.status_code, response.text))
                    else:
                        helper.log_debug('JIRA issue successfully added to the backlog collection. '
                                        'content={}'.format(response.text))

                    # Manage attachment
                    if jira_attachment in ("enabled_csv"):
                        attach_csv(helper, jira_root_url, jira_created_key, jira_attachment_token, jira_headers_attachment, ssl_certificate_validation, proxy_dict)

                    elif jira_attachment in ("enabled_json"):
                        attach_json(helper, jira_root_url, jira_created_key, jira_attachment_token, jira_headers_attachment, ssl_certificate_validation, proxy_dict)

                    elif jira_attachment in ("enabled_xlsx"):
                        attach_xlsx(helper, jira_root_url, jira_created_key, jira_attachment_token, jira_headers_attachment, ssl_certificate_validation, proxy_dict)


                # Return the JIRA response as final word
                return jira_creation_response
