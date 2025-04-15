import import_declare_test

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    SingleModel,
)
from splunktaucclib.rest_handler import admin_external, util
from ta_service_desk_simple_addon_rh_account_handler import (
    CustomRestHandlerCreateRemoteAccount,
)
import logging

util.remove_http_proxy_env_vars()


special_fields = [
    field.RestField(
        "name",
        required=True,
        encrypted=False,
        default=None,
        validator=validator.AllOf(
            validator.String(
                max_len=50,
                min_len=1,
            ),
            validator.Pattern(
                regex=r"""^[a-zA-Z]\w*$""",
            ),
        ),
    )
]

fields = [
    field.RestField(
        "jira_url",
        required=True,
        encrypted=False,
        default=None,
        validator=validator.Pattern(
            regex=r"""^https?://.*""",
        ),
    ),
    field.RestField(
        "username",
        required=True,
        encrypted=False,
        default=None,
        validator=validator.Pattern(
            regex=r"""^.*$""",
        ),
    ),
    field.RestField(
        "password",
        required=True,
        encrypted=True,
        default=None,
        validator=validator.Pattern(
            regex=r"""^.*$""",
        ),
    ),
    field.RestField(
        "configuration_help_link",
        required=False,
        encrypted=False,
        default=None,
        validator=None,
    ),
    field.RestField(
        "jira_auth_mode",
        required=True,
        encrypted=False,
        default="basic",
        validator=None,
    ),
    field.RestField(
        "using_api_token_help_link",
        required=False,
        encrypted=False,
        default=None,
        validator=None,
    ),
    field.RestField(
        "using_pat_help_link",
        required=False,
        encrypted=False,
        default=None,
        validator=None,
    ),
    field.RestField(
        "jira_ssl_certificate_path",
        required=False,
        encrypted=False,
        default=None,
        validator=validator.Pattern(
            regex=r"""^.*$""",
        ),
    ),
    field.RestField(
        "jira_ssl_certificate_pem",
        required=False,
        encrypted=False,
        default=None,
        validator=validator.Pattern(
            regex=r"""^.*$""",
        ),
    ),
    field.RestField(
        "ssl_help_link", required=False, encrypted=False, default=None, validator=None
    ),
]
model = RestModel(fields, name=None, special_fields=special_fields)


endpoint = SingleModel(
    "ta_service_desk_simple_addon_account", model, config_name="account"
)


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=CustomRestHandlerCreateRemoteAccount,
    )
