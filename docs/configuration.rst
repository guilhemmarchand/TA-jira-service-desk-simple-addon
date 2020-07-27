Configuration
#############

*Configuration page:*

.. image:: img/config1.png
   :alt: config1.png
   :align: center

Configure your JIRA instance
============================

**Enter the configuration page in the UI to setup the JIRA instance URL and credentials to be used.**

The Splunk Add-on for JIRA service desk implements basic authentication as described here:

- https://developer.atlassian.com/server/jira/platform/basic-authentication
- https://developer.atlassian.com/cloud/jira/service-desk/basic-auth-for-rest-apis

**The JIRA instance configuration requires:**

- The JIRA URL which is https enforced, you can define the instance without the protocol like "myjira.mydomain.com" or "https://myjira.domain.com"
- The user name to be used for authentication
- The secret token defined for this user

Optionally you can request for SSL certificates validation during the REST call made to JIRA api during the issue creation, which will require the certificates of the instance to be fully valid.

Logging level
=============

The logging level can be defined within the configuration page too, the application makes a real usage of the debug mode and will generate many more messages in debug.

In normal circumstances, the logging level should be defined to INFO, required logging level will automatically be used when any unexpected error is encountered.

Validating the connectivity
===========================

**You can validate the connectivity very easily by opening any of the JIRA Get information reports, which achieve rest calls to the JIRA API to retrieve different information such as the list of projects available:**

.. image:: img/config_getprojects.png
   :alt: config_getprojects.png
   :align: center

Shall the connectivity be effective and if you open the Get projects report, the list of the JIRA projects available for your JIRA instance appears in the table.

::

| jirafill opt=1 | stats count by key, key_projects

If the command returns the list of your JIRA projects, then the connectivity is successful:

.. image:: img/config3.png
   :alt: config3.png
   :align: center

**You can as well simulate the creation of an alert and action the JIRA Service Desk:**

- Enter a search window
- type ``|makeresults``
- Click save as new alert
- Scroll down to alert actions and add the JIRA Service Desk action

.. image:: img/config2.png
   :alt: config2.png
   :align: center

**Testing access and authentication with curl:**

You can as well very easily achieve a test with curl from the search head:

::

    curl -k https://<jira_url>/rest/api/latest/project --user <jira_username>:<jira_password>

Which, if successful, will return in a JSON format the list of projects available in your JIRA instance.

Using the alert action for non admin users
==========================================

**For non admin users to be able to use the alert action, the following role is provided out of the box:**

- jira_alert_action

This role needs to be inherited for the users, or your users to be member of this role.

**The role provides:**

- capability ``list_storage_passwords``
- capability ``list_settings``
- write permission to the resilient KVstore ``kv_jira_failures_replay``
