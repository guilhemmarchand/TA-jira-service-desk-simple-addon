import import_declare_test
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
import json
import os
import sys
import requests

# get the SPLUNK_HOME environment variable
splunkhome = os.environ["SPLUNK_HOME"]

# add the lib directory to the sys.path
sys.path.append(
    os.path.join(splunkhome, "etc", "apps", "TA-jira-service-desk-simple-addon", "lib")
)

# import least privileges access libs
from ta_jira_libs import (
    jira_get_conf,
)


class CustomRestHandlerCreateRemoteAccount(AdminExternalHandler):
    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    def checkConnectivity(self):
        # get conf
        jira_conf = jira_get_conf(self.getSessionKey(), self.handler._splunkd_uri)

        # Call the validate_connection endpoint
        header = {
            "Authorization": f"Splunk {self.getSessionKey()}",
            "Content-Type": "application/json",
        }

        url = (
            "%s/services/jira_service_desk/manager/validate_connection"
            % self.handler._splunkd_uri
        )
        data = {
            "jira_url": self.payload.get("jira_url"),
            "auth_mode": self.payload.get("jira_auth_mode"),
            "username": self.payload.get("username"),
            "jira_password": self.payload.get("password"),
            "jira_ssl_certificate_path": self.payload.get("jira_ssl_certificate_path"),
            "jira_ssl_certificate_pem": self.payload.get("jira_ssl_certificate_pem"),
        }

        try:
            response = requests.post(
                url,
                headers=header,
                data=json.dumps(data, indent=1),
                verify=False,  # local splunkd API
                timeout=300,
                proxies=None,  # Never use proxy for local Splunk API calls
            )

            # Parse the response
            try:
                response_data = response.json()
            except:
                response_data = None

            # If we have a response with error details, use those
            if response_data and isinstance(response_data, dict):
                if "payload" in response_data and isinstance(
                    response_data["payload"], dict
                ):
                    if "response" in response_data["payload"]:
                        raise Exception(response_data["payload"]["response"])
                    elif "error" in response_data["payload"]:
                        raise Exception(response_data["payload"]["error"])
                    elif "message" in response_data["payload"]:
                        raise Exception(response_data["payload"]["message"])

            # If we get a non-200 status code, raise an exception
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")

        except requests.exceptions.RequestException as e:
            # If we have a response object, try to get the error details
            if hasattr(e, "response") and e.response is not None:
                try:
                    error_data = e.response.json()
                    if "payload" in error_data and isinstance(
                        error_data["payload"], dict
                    ):
                        if "response" in error_data["payload"]:
                            raise Exception(error_data["payload"]["response"])
                        elif "error" in error_data["payload"]:
                            raise Exception(error_data["payload"]["error"])
                        elif "message" in error_data["payload"]:
                            raise Exception(error_data["payload"]["message"])
                except:
                    if e.response.text:
                        raise Exception(e.response.text)

            # If we couldn't extract a specific error message, use the original error
            raise Exception(f"Failed to connect to JIRA: {str(e)}")

    def handleList(self, confInfo):
        AdminExternalHandler.handleList(self, confInfo)

    def handleEdit(self, confInfo):
        self.checkConnectivity()
        AdminExternalHandler.handleEdit(self, confInfo)

    def handleCreate(self, confInfo):
        self.checkConnectivity()
        AdminExternalHandler.handleCreate(self, confInfo)

    def handleRemove(self, confInfo):
        AdminExternalHandler.handleRemove(self, confInfo)
