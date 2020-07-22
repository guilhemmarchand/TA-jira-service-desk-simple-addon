Release notes
#############

Version 1.0.13
==============

- fix: remove the automatic addition of the result link in the description field as it systematically creates a different JIRA content, which creates confusion with the dedup JIRA option
- fix: change in configuration app the sentence "JIRA token password" to "JIRA password" to avoid confusion between basic authentication and OAuth2 which isn't used by the Add-on
- fix: in some custom configuration, the custom command jiragetfields would not return the expected results, the type of issue is removed from the rest call to retrieve all fields information on a per project basis instead

Version 1.0.12
==============

- Feature: Issue #18 - New option on a per alert basis allows automatically attaching Splunk alert results to the JIRA issue in CSV or JSON format
- Feature: Issue #18 - Add by default in the description field the result link token call

Version 1.0.11
==============

- Feature: Issue #12 - New JIRA deduplication feature workflow allows handling automatically on a per alert basis updating JIRA issues by the addition of a comment (that can be controlled) to the original issue, instead of creating duplicated JIRA issues
- Feature: Issue #15 - Adding support for components definition on a per alert basis, components can now be defined by their name in a comma separated format within alerts
- Feature: Upgrade of Jinja2 2.11.2 libraries to address vulnerabilities reported during Splunk Cloud app vetting process
- Feature: Upgrade of PyYAML 5.3.1 libraries to address vulnerabilities reported during Splunk Cloud app vetting process
- Feature: Upgrade of httplib2-0.18.1 libraries to address vulnerabilities reported during Splunk Cloud app vetting process
- Feature: Upgrade of urllib3-1.25.9 libraries to address vulnerabilities reported during Splunk Cloud app vetting process

Version 1.0.10
==============

- Fix: Issue #9 - Parsing failure in custom field section with non standard fields in between square brackets

Version 1.0.9
=============

- Fix: Issue #11 - SSL verification disablement is not honoured properly and remains active even if the checkbox is not checked
- Change: app.manifest schema upgrade to 2.0.0 to ease Cloud automated deployments

Version 1.0.8
=============

- Fix: Allows defining non custom fields in the custom section, such as builtin non standard fields (Components) that would have been made required by JIRA admins

Version 1.0.7
=============

- Fix: Default timed out value during REST calls are too short and might lead to false positive failures and duplicated creation of JIRA issues

Version 1.0.6
=============

- Change: For Splunk Cloud vetting purposes, explicit Python3 mode in restmap.conf handler

Version 1.0.5
=============

- Fix: Provide an embedded role jira_alert_action that can be inherited for non admin users to be allowed to fire the action and work with the resilient store feature

Version 1.0.4
=============

- Feature: resilient store improvements, catch all failures and exceptions during issue creation attempts
- Fix: minor fix in resilient store table
- Fix: remove redundant alert link in nav bar

Version 1.0.3
=============

- Fix Issue #2: Avoids error messages on indexers in distributed mode to report error messages on jirafill and jiragetfields custom commands due to enabled distributed mode
- Fix Issue #2: Avoids error messages reported during execution of jirafill and jiragetfields custom commands related to insecure HTTP calls with urllib3

Version 1.0.2
=============

- Feature: Support for Web Proxy
- Feature: Full support for Python 3 (migration to newer Add-on builder libs, embedded custom commands)
- Fix: Support defining the JIRA instance URL with or without https://
- Fix: Potential creation failure with number type custom fields
- Fix: Metadata avoid sharing alerts, reports and views at global level
- Fix: Help block appears right shifted within Enterprise Security correlation search editor, but centered properly in Splunk core alert editor

Version 1.0.1
=============

- unpublished

Version 1.0.0
=============

- initial and first public release
