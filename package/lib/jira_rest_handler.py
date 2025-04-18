#!/usr/bin/env python
# coding=utf-8

import re
import json
from urllib.parse import urlparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from splunk.persistconn.application import PersistentServerConnectionApplication


class RequestInfo(object):
    """
    This represents the request.
    """

    def __init__(
        self,
        user,
        session_key,
        system_authtoken,
        server_rest_uri,
        server_rest_host,
        server_rest_port,
        server_hostname,
        server_servername,
        connection_src_ip,
        connection_listening_port,
        method,
        path,
        query,
        raw_args,
    ):
        self.user = user
        self.session_key = session_key
        self.system_authtoken = system_authtoken
        self.server_rest_uri = server_rest_uri
        self.server_rest_host = server_rest_host
        self.server_rest_port = server_rest_port
        self.server_hostname = server_hostname
        self.server_servername = server_servername
        self.connection_src_ip = connection_src_ip
        self.connection_listening_port = connection_listening_port
        self.method = method
        self.path = path
        self.query = query
        self.raw_args = raw_args


class RESTHandler(PersistentServerConnectionApplication):
    """
    This is a REST handler base-class that makes implementing a REST handler easier.

    This works by resolving a name based on the path in the HTTP request and calls it. This class
    will look for a function that includes the HTTP verb followed by the path.abs

    For example, if a GET request is made to the endpoint is executed with the path
    /lookup_edit/lookup_contents, then this class will attempt to run a function named
    get_lookup_contents(). Note that the root path of the REST handler is removed.

    If a POST request is made to the endpoint is executed with the path
    /lookup_edit/lookup_contents, the this class will attempt to execute post_lookup_contents().

    The arguments to the function will be the following:

      * request_info (an instance of RequestInfo)
      * keyword arguments (**kwargs)
    """

    def __init__(self, command_line, command_arg, logger=None):
        self.logger = logger
        PersistentServerConnectionApplication.__init__(self)

    @classmethod
    def get_function_signature(cls, method, path):
        """
        Get the function that should be called based on path and request method.
        """

        if len(path) > 0:
            return method + "_" + re.sub(r"[^a-zA-Z0-9_]", "_", path).lower()
        else:
            return method

    def render_json(self, data, response_code=200, headers=None):
        """
        Render the data as JSON
        """

        combined_headers = {"Content-Type": "application/json"}

        if headers is not None:
            combined_headers.update(headers)

        return {
            "payload": json.dumps(data),
            "status": response_code,
            "headers": combined_headers,
        }

    def render_error_json(self, message, response_code=500):
        """
        Render an error to be returned to the client.
        """

        data = {"success": False, "message": message}

        return {
            "payload": json.dumps(data),
            "status": response_code,
            "headers": {"Content-Type": "application/json"},
        }

    def get_forms_args_as_dict(self, form_args):
        post_arg_dict = {}

        for arg in form_args:
            name = arg[0]
            value = arg[1]

            post_arg_dict[name] = value

        return post_arg_dict

    def handle(self, in_string):
        try:
            # log
            self.logger.debug("trackme_rest_handler, handling incoming request.")

            # Parse the arguments
            args = self.parse_in_string(in_string)

            #
            # user info - add to request_info
            #

            session_key = args["session"]["authtoken"]
            user = args["session"]["user"]

            #
            # system auth
            #

            # If passSystemAuth = True, add system_authtoken
            try:
                system_authtoken = args["system_authtoken"]
            except Exception as e:
                system_authtoken = None

            #
            # server info
            #

            server_rest_uri = args["server"]["rest_uri"]

            # extract rest host and port
            parsed_uri = urlparse(server_rest_uri)
            server_rest_host = parsed_uri.hostname
            server_rest_port = parsed_uri.port

            server_hostname = args["server"]["hostname"]
            server_servername = args["server"]["servername"]

            #
            # connection info
            #

            connection_src_ip = args["connection"]["src_ip"]
            connection_listening_port = args["connection"]["listening_port"]

            #
            # http method
            #

            # Get the method
            method = args["method"]

            # Get the path and the args
            if "path_info" in args:
                path = args["path_info"]
            else:
                return {"payload": "No path was provided", "status": 403}

            if method.lower() == "post":
                # Load the parameters from the query
                query = args["query_parameters"]

                if query is None:
                    query = {}

                # Apply the ones (if any) we got from the form
                query_form = self.get_forms_args_as_dict(args["form"])

                if query_form is not None:
                    query.update(query_form)
            else:
                query = args["query_parameters"]

            #
            # finally add to the request_info
            #

            # Make the request info object
            request_info = RequestInfo(
                user,
                session_key,
                system_authtoken,
                server_rest_uri,
                server_rest_host,
                server_rest_port,
                server_hostname,
                server_servername,
                connection_src_ip,
                connection_listening_port,
                method,
                path,
                query,
                args,
            )

            # Get the function signature
            function_name = self.get_function_signature(method, path)

            try:
                function_to_call = getattr(self, function_name)
            except AttributeError:
                function_to_call = None

            # Try to run the function
            if function_to_call is not None:
                if self.logger is not None:
                    self.logger.debug("Executing function, name=%s", function_name)

                # Execute the function
                return function_to_call(request_info, **query)
            else:
                if self.logger is not None:
                    self.logger.warn(
                        "A request could not be executed since the associated function "
                        + "is missing, name=%s",
                        function_name,
                    )

                return {"payload": "Path was not found", "status": 404}
        except Exception as exception:
            if self.logger is not None:
                self.logger.exception(
                    "Failed to handle request due to an unhandled exception"
                )

            return {"payload": str(exception), "status": 500}

    def convert_to_dict(self, query):
        """
        Create a dictionary containing the parameters.
        """
        parameters = {}

        for key, val in query:
            # If the key is already in the list, but the existing entry isn't a list then make the
            # existing entry a list and add thi one
            if key in parameters and not isinstance(parameters[key], list):
                parameters[key] = [parameters[key], val]

            # If the entry is already included as a list, then just add the entry
            elif key in parameters:
                parameters[key].append(val)

            # Otherwise, just add the entry
            else:
                parameters[key] = val

        return parameters

    def parse_in_string(self, in_string):
        """
        Parse the in_string
        """

        params = json.loads(in_string)

        params["method"] = params["method"].lower()

        params["form_parameters"] = self.convert_to_dict(params.get("form", []))
        params["query_parameters"] = self.convert_to_dict(params.get("query", []))

        return params
