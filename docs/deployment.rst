Deployment & Upgrades
#####################

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

There are currently no dependencies for the application.

However, if you deploy the Splunk_SA_CIM package, make sure you have declared the ``cim_modactions`` index as the Add-on logs would automatically be directed to this index is the SA CIM application is installed on the search heads.

If the Splunk_SA_CIM is not installed, the Add-on logs will be generated in the ``_internal`` index. (This is a normal behaviour for Add-on developped with the Splunk Add-on builder that provide adaptive response capabilities)

Initial deployment
==================

**The deployment of the Splunk application is very straight forward:**

- Using the application manager in Splunk Web (Settings / Manages apps)

- Extracting the content of the tgz archive in the "apps" directory of Splunk

- For SHC configurations (Search Head Cluster), extract the tgz content in the SHC deployer and publish the SHC bundle

Upgrades
========

Upgrading the Splunk application is pretty much the same operation than the initial deployment.

All of TrackMe components and configuration items are upgraded resilient, in respects with Splunk configuration good practices.

Upgrade from version 1.x.x to 2.x.x
===================================

.. warning:: **BREAKING CHANGES!**

    - The major release 2.0 migrates from the Splunk Add-on Builder framework to the Splunk add-on-ucc-framework.
    - This fundamentally changes the way accounts are handled automatically, which means that once the upgrade has been performed you need to re-create your account(s) defining the connectivity to JIRA before alert actions can trigger again.

**Proceed as follows:**

- Upgrade the Add-on to the latest release 2.x available
- Restart the Splunk search head (or automatic rolling restart in Search Head Cluster)
- Access to the configuration page, and re-create your connection to JIRA (not that in version 2.x you can setup multiple accounts)
- Verify that the connection is successful
- Optionnally verify either that an existing alert can trigger a JIRA ticket, or create a temporary test alert
