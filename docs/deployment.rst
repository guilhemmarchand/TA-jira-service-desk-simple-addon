Deployment & Requirements
#########################

Deployment matrix
=================

+----------------------+---------------------+
| Splunk roles         | required            |
+======================+=====================+
| Search head          |   yes               |
+----------------------+---------------------+
| Indexer tiers        |   no                |
+----------------------+---------------------+

If Splunk search heads are running in Search Head Cluster (SHC), the Splunk application must be deployed by the SHC deployer.

Dependencies
============

There are currently no dependencies for the application, but as with any Splunk modular action, the Splunk CIM application should be installed on the search heads. (``Splunk_SA_CIM``)

Make sure you have declared the ``cim_modactions`` index as the Add-on logs would automatically be directed to this index is the SA CIM application is installed on the search heads.

If the Splunk_SA_CIM is not installed, the Add-on logs will be generated in the ``_internal`` index. (This is a normal behaviour for Add-on developped with the Splunk Add-on builder that provide adaptive response capabilities)

Role Based Access Control (RBAC)
================================

Since the release 2.1.0, the JIRA application leverages a least privilege approach using its internal REST API, this allows you to allow users to access and use the alert actions with no other capabilities than the builtin capability ``jira_service_desk``.

**How things work:**

- The application defines a capability called ``jira_service_desk``.
- This capability is enabled in the builtin role ``jira_alert_action``.
- The builtin role ``jira_alert_action`` is automatically inherited for the ``admin`` and ``sc_admin`` roles.
- When calling the action, the backend underneath automatically call the JIRA App REST endpoints which access is constrained by the ``jira_service_desk`` capability.
- These endpoints provide the necessary information to the JIRA App to allow the alert actions to work.

**How to allow normal users to use the alert actions:**

- To allow normal users to use the alert actions, you can directly inherit the ``jira_alert_action`` role in their role definition.
- Alertnatively, You can also natively add the ``jira_service_desk`` capability to the existing roles.
- Both approaches are equivalent.

**What does provide the builtin jira_service_desk capability and the jira_alert_action role:**

- The capability ``jira_service_desk`` and the associated role provide **nothing** except the access to the JIRA App REST endpoints, allowing the alert actions to work.


Initial deployment
==================

**The deployment of the Splunk application is very straight forward:**

- Using the application manager in Splunk Web (Settings / Manages apps)

- Extracting the content of the tgz archive in the "apps" directory of Splunk

- For SHC configurations (Search Head Cluster), extract the tgz content in the SHC deployer and publish the SHC bundle

Upgrades
========

Upgrading the Splunk application is pretty much the same operation than the initial deployment.
