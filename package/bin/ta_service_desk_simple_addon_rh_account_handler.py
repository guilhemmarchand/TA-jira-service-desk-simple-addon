import import_declare_test
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
import json
import requests


class CustomRestHandlerCreateRemoteAccount(AdminExternalHandler):
    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    def checkConnectivity(self):
        # Call the validate_connection endpoint
        header = {
            "Authorization": "Splunk %s" % self.getSessionKey(),
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
            "ssl_certificate_path": self.payload.get("ssl_certificate_path"),
        }

        # check connectivity, raise an exception if the connectivity check fails
        try:
            response = requests.post(
                url,
                headers=header,
                data=json.dumps(data, indent=1),
                verify=False,
                timeout=300,
            )
            response.raise_for_status()

        except Exception as e:

            try:
                response_json = json.loads(response.text)
            except Exception as e:
                response_json = {"response": response.text}

            raise Exception(
                f'JIRA connectivity validation has failed, response.status_code="{response.status_code}", response="{json.dumps(response_json, indent=2)}", jira_url="{self.payload.get("jira_url")}", auth_mode="{self.payload.get("jira_auth_mode")}", username="{self.payload.get("username")}", ssl_certificate_path="{self.payload.get("ssl_certificate_path")}"'
            )

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
