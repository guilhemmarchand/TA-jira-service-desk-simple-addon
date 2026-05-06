Compatibility
=============

Splunk compatibility
####################

This application is compatible with Splunk Enterprise 9.2.x and later (Python 3.9), Splunk Enterprise 10.x (Python 3.9), Splunk Enterprise 10.2.x (Python 3.13), and Splunk Cloud (Victoria Experience).

Splunk Enterprise 9.1.x users must run the search head on Python 3.9 (supported but not the default on 9.1.x — see Splunk's `Python 3 Migration <https://docs.splunk.com/Documentation/Splunk/9.1.0/Python3Migration/AboutMigration>`_ documentation for how to switch). The bundled runtime libraries shipped in the add-on (``requests``, ``splunktaucclib``, ``solnlib``, etc.) require Python 3.9 or later; running the add-on under the legacy Python 3.7 interpreter on Splunk 9.1.x is not supported.

Splunk Enterprise Security compatibility
########################################

This application has been verified with ES 7.x/8.x.

Python support
##############

Only Python 3 is supported. The add-on declares ``python.required = 3.9,3.13`` and is therefore loaded by both Python 3.9 (Splunk 9.x / 10.x) and Python 3.13 (Splunk Enterprise 10.2+).

Web Browser compatibility
#########################

The application can be used with any of the supported Web Browser by Splunk:

https://docs.splunk.com/Documentation/Splunk/latest/Installation/Systemrequirements

JIRA compatibility
##################

The Add-on is compatible with all JIRA products, notably:

- JIRA Server
- JIRA Cloud
- JIRA Data center
