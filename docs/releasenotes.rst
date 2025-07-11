Release notes
#############

Version 2.1.1
=============

- bug - basic authentication is unexpectly used due to a bug in 2.1.0 which affects Jira on-premise instances #215
- bug - dedup get Jira issue failed due to invalid credentials #216

Version 2.1.0
=============

Key information
---------------

- This release introduces a REST API in the application, with the principal objectives of implementing a least privileve approach to allow the actions to be called with restricted capabilities, and avoid problematic capabilities previously required.
- This also provides a centralised API logic, these endpoints are globally called by the associated custom commands and alert actions.
- Deep review and refactoring of the Python code was achieved.
- New capabilities were added to the JIRA alert actions notably with Auto Closure of issues.
- Automated validation of the JIRA connectivity before allowing the creation or update of a JIRA account.
- SSL validation with custom or self-signed certificate by providing the SSL bundle content in the account configuration.

Detailed release notes
----------------------

- bug - Unreadable characters after adding alert data in JSON to the description #203
- change - Define fields type in collections.conf #204
- enhancement - Prevent REST API populating searches executed to populate the alert drilldown to be executed without a restricted time range, so Workload rules forbidding all time searches would not prevent dropdown from being populated #205
- enhancements/bugs - Various Python code review and refresh #206
- enhancement - Least Privilege approach and removing needs for privileged capabilities in Splunk #207
- enhancement - Validates the JIRA connectivity before allowing the creation or update of a JIRA account #209
- enhancement - Add built-in support for Issue auto-closure with new auto closure capabilities #210
- enhancement - SSL validation with custom or self-signed certificate by providing the SSL bundle content in the account configuration #212

Version 2.0.20
==============

- Issue dedup no longer works after Atlassian put cloudfront in front of the Jira cloud api #200

Version 2.0.19
==============

- Fix Issue#181 - Fix - Problem setting Assets custom field object #181
- Fix Issue#194 - Enhancement - Result alerts in description as table #194
- Fix Issue#197 - FIPS Support since Splunk 9.3.x - FIPS error when creating tickets #197
- Change - Upgrade all SDKs and Libraries to latest versions
- Change - Dark theme support for Configuration

Version 2.0.18
==============

- Fix Issue#184 - Fix - Splunk Cloud vetting - Force SSL Verification or the use of a CA bundle to validate the SSL verification #184
- Fix Issue#185 - Build - Prevents pyc, hidden files or directory to be part of the release #185
- Fix Issue#186 - Pypi requirements libs refresh #186
- Fix Issue#188 - Number of projects count in Overview - JIRA Projects is wrong #188
- Fix Issue#189 - Avoid app nav bar ending in multiple lines #189

Version 2.0.17
==============

- enhancement - Custom fields - Add additional protection against badly parsed custom fields #174
- enhancement - Allows adding the Splunk search results in the JIRA Description field (in CSV or JSON format) #173
- bug - Splunk Cloud Classic - ensures that indexed time parsing is partioned on the Search Heads properly (SLIM) #176

Version 2.0.16
==============

- enhancement - Remove __mv_ fields from export as JSON/XLSX/CSV when attaching results #170

Version 2.0.14
==============

- Fix Issue #155: Regression with the resilient store tracker

If post-upgrade and after at leat one execution you are still experiencing issues with the reslient tracker, please purge the KVstore collection:

::

    | outputlookup jira_failures_replay

Any temporary failure will be stored properly for replay purposes.

Version 2.0.13
==============

- FIx Issue #151: Proxy account configuration is not synced in a SHC

Version 2.0.12
==============

- Fix Issue #148: Accounts are not synchronised among members of the SHC
- Fix Issue #149: jiraoverview should verify the HTTPS protocol

Version 2.0.11
==============

- Enhancement: Add a connectivity verification (network, settings and authentication) in custom commands, as well as an option that can be triggered from the jirafill command (| )
- Enhancement: Logging enhancements, custom command now log to their own dedicated log file, available in the _internal, configurable via the logging level in the configuration UI, and easily accessible from the navigation menu
- Enhancement: Introducing a new custom command "| jiraoverview" which loads at scale all main KPIs for all projects for configured accounts, and replaces the previous heavy and slow logic in the JIRA analytic dashboard. In Addition, this addresses some reported issues where not all projects could be loaded
- Fix: Regression with version 2.10 regarding issues calling components #146

Version 2.0.10
==============

- Python code level enhancements for a more robust approach when builing the JSON data to be submitted to the JIRA API, this addresses risks of failures with very complex contents
- Remove useless references to oauth in account configuration

Version 2.0.9
=============

.. warning:: **BREAKING CHANGES!**

    - The new major release uses a new framework (add-on-ucc-framework) which changes the way accounts are handled by the application
    - Post upgrade, **you need to setup the connectivity to your JIRA instance(s) again** before the Add-on can be used
    - Existing alerts will not work anymore until you perform the account setup
    - You do not need to update the alerts themselves as these remain compatible from version 1.x to version 2.x

**What's new in the Add-on for JIRA version 2.0.x:**

- Fix Issue #133 - Ticket creation fails if a message contains a non latin-1 character

Version 2.0.7
=============

.. warning:: **BREAKING CHANGES!**

    - The new major release uses a new framework (add-on-ucc-framework) which changes the way accounts are handled by the application
    - Post upgrade, **you need to setup the connectivity to your JIRA instance(s) again** before the Add-on can be used
    - Existing alerts will not work anymore until you perform the account setup
    - You do not need to update the alerts themselves as these remain compatible from version 1.x to version 2.x

**What's new in the Add-on for JIRA version 2.0.x:**

- Fix Issue #121 - missing id section in app.conf was reported to be causing issues in Splunk Cloud automation

Version 2.0.6
=============

.. warning:: **BREAKING CHANGES!**

    - The new major release uses a new framework (add-on-ucc-framework) which changes the way accounts are handled by the application
    - Post upgrade, **you need to setup the connectivity to your JIRA instance(s) again** before the Add-on can be used
    - Existing alerts will not work anymore until you perform the account setup
    - You do not need to update the alerts themselves as these remain compatible from version 1.x to version 2.x

**What's new in the Add-on for JIRA version 2.0.x:**

Version 2.0.5
=============

.. warning:: **BREAKING CHANGES!**

    - The new major release uses a new framework (add-on-ucc-framework) which changes the way accounts are handled by the application
    - Post upgrade, **you need to setup the connectivity to your JIRA instance(s) again** before the Add-on can be used
    - Existing alerts will not work anymore until you perform the account setup
    - You do not need to update the alerts themselves as these remain compatible from version 1.x to version 2.x

**What's new in the Add-on for JIRA version 2.0.x:**

- Enhancement: Issue #116 - Improve JIRA Cloud account configuration steps

Version 2.0.4
=============

.. warning:: **BREAKING CHANGES!**

    - The new major release uses a new framework (add-on-ucc-framework) which changes the way accounts are handled by the application
    - Post upgrade, **you need to setup the connectivity to your JIRA instance(s) again** before the Add-on can be used
    - Existing alerts will not work anymore until you perform the account setup
    - You do not need to update the alerts themselves as these remain compatible from version 1.x to version 2.x

**What's new in the Add-on for JIRA version 2.0.x:**

- Fix: Issue #112 - In release 1.0.x, the priority field was made optional (Issue #42) to address some specific use cases, but this setting was lost during the transition to ucc-libs

Version 2.0.3
=============

.. warning:: **BREAKING CHANGES!**

    - The new major release uses a new framework (add-on-ucc-framework) which changes the way accounts are handled by the application
    - Post upgrade, **you need to setup the connectivity to your JIRA instance(s) again** before the Add-on can be used
    - Existing alerts will not work anymore until you perform the account setup
    - You do not need to update the alerts themselves as these remain compatible from version 1.x to version 2.x

**What's new in the Add-on for JIRA version 2.0.x:**

- Fix Issue #108 - Splunk Cloud vetting is failing since new major release 2.0 (store the bearer token in the credential store, avoid logging of the token)
- If you had previously setup a distributed configuration, you need to re-enter the bearer token
- This release addresses Splunk Cloud vetting failures since the major release 2.0

Version 2.0.2
=============

.. warning:: **BREAKING CHANGES!**

    - The new major release uses a new framework (add-on-ucc-framework) which changes the way accounts are handled by the application
    - Post upgrade, **you need to setup the connectivity to your JIRA instance(s) again** before the Add-on can be used
    - Existing alerts will not work anymore until you perform the account setup
    - You do not need to update the alerts themselves as these remain compatible from version 1.x to version 2.x

**What's new in the Add-on for JIRA version 2.0.x:**

- Fix - Issue #106 - Windows specific - Addon writing output CSV into Windows\TEMP folder

Version 2.0.1
=============

.. warning:: **BREAKING CHANGES!**

    - The new major release uses a new framework (add-on-ucc-framework) which changes the way accounts are handled by the application
    - Post upgrade, **you need to setup the connectivity to your JIRA instance(s) again** before the Add-on can be used
    - Existing alerts will not work anymore until you perform the account setup
    - You do not need to update the alerts themselves as these remain compatible from version 1.x to version 2.x

**What's new in the Add-on for JIRA version 2.0.x:**

- Fix Appinspect warning check_reload_trigger_for_all_custom_confs #104

Version 2.0.0
=============

.. warning:: **BREAKING CHANGES!**

    - The new major release uses a new framework (add-on-ucc-framework) which changes the way accounts are handled by the application
    - Post upgrade, **you need to setup the connectivity to your JIRA instance(s) again** before the Add-on can be used
    - Existing alerts will not work anymore until you perform the account setup
    - You do not need to update the alerts themselves as these remain compatible from version 1.x to version 2.x

**What's new in the Add-on for JIRA version 2.0.0:**

- Migration to ucc-gen (Splunk Add-on factory framework), refreshed modern configuration UI
- Support for JIRA multi tenant accounts (Multiple JIRA accounts can now be set up targeting different JIRA instances)
- Support for Personal Access Token (PAT) authentication (See: https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html)
- Support for Proxy authentication
- Python 3 only support (Splunk 7.x is not supported any longer)
- Jquery migration
- Improved distributed setup with bearer based remote KVstore feature relying on the replay KVstore (for setups where JIRA is not available from the main Splunk search heads)
- Support for attachments in Excel (xlsx) format
- Support for attachments with the issue dedup feature
- Fix - Issue #102 - Issue in dedup behaviour when dedup is enabled but the issue was resolved, closed or cancelled

Version 1.0.30
==============

- Enhancement: Issue #91 - proxy support for jirarest.py and jirafill.py #91 (Author: 8lex)
- Enhancement: Issue #92 - provide an SSL certificate path option for internal PKI certificate validation, honour SSL certificate validation in custom commands
- Enhancement: Issue #93 - attachments are now supported when using a proxy
- Enhancement: Issue #94 - Specify latest rather than static version 2 in API REST calls to allow last API version to be used when available

Version 1.0.29
==============

- Enhancement: jirarest supports additional method for extended JIRA integration #85 (Author: Rémi Séguy)

Version 1.0.28
==============

- Change: Issue #83 - Python Upgrade Readiness App complains about 'outdated Python SDK'

Version 1.0.27
==============

- Fix: Issue #77 - Error reported in logs when the issue MD5 is equal, the alert continues to trigger and dedup is disabled

Version 1.0.26
==============

- Feature: Issue #72 - Provides a new mode called passthrough mode, which is designed for scenarios where Splunk cannot contact the JIRA instance directly for security or restrictions purposes (such as Splunk Cloud potentially). A second Splunk instance that can connect to JIRA instance would recycle the replay KVstore content to perform the final call. 
- Enhancement: Issue #73 - Provides custom search auto description (searchbnf.conf)

Version 1.0.25
==============

- Change: Issue #70 - Splunk Python SDK upgrade to 1.6.15

Version 1.0.24
==============

- Feature: Issue #65 - Allows defining the JIRA Issue reporter

Version 1.0.23
==============

- Fix: Issue #61 - Custom commands now require Python3 mode explicity which with AoB py3 SDK version causes error messages on the indexers #61

Version 1.0.22
==============

- Fix: For Splunk Cloud vetting purposes, commands.conf needs to specify python3 explicitly

Version 1.0.21
==============

- Fix: Issue #54 - Appinspect failure due to missing key in spec file
- Fix: Issue #55 - Appinspect failure in reports using the jirarest command due to checks attempting to run the run the reports in non JIRA connected environments, causing the map command to return an error
- Feaure: Issue #56 - New Overview JIRA analytic view relying on the new jirarest command that allows live REST calls to JIRA and execution of JQL queries #56

Version 1.0.20
==============

- Fix: Issue #50 - Deduplication Creating One Duplicate After Item Closed #50

Version 1.0.19
==============

- Feature: Issue #33 - Exclude closed statuses from the JIRA dedup behavior, to prevent deduplicating closed issues, which list can be customised if required (defaults to Closed,Completed,Canceled)
- Feature: Issue #34 - Provides granular control against the content to be taken into account for dedup behavior and the md5 calculation used to identify duplicated tickets
- Feature: Provide a new REST API custom command wrapper to allow performing any get call against any endpoint of the JIRA API, provides a builting issue statistic report that can be used with collect/mcollect to index issues statistics, provide a new dashboard exposing the wrapper usage
- Feature: Jira get field report split into two reports, one for all projects, one report providing results per project
- Fix: Issue #41 - Incident Review Manual AR Issue #41
- Fix: default.meta does not define permissions for the builtin jira_admin role for the JIRA issue backlog collection used for the dedup feature
- Change: Issue #42 - Removing Priority as a Required Input #42
- Change: Improved rendering of options and clearness for required inputs in the alert definition
- Change: Issue #16 - Deprecation of jiragetfields custom command, which is replaced with calls to the new REST wrapper jirarest

Version 1.0.18
==============

- Fix: ensure aob configuration replicates in shc environment

Version 1.0.17
==============

- feature: Enable / Disable custom fields structure parsing new alert option, disabling the custom fields parsing can be useful when the backend fails to parse properly a custom fields structure that is not expected

Version 1.0.16
==============

- fix: Splunk Cloud vetting refused due to a remaining https protocol check in jiragetfields.py, checking if the URI contains https rather than starts with https

Version 1.0.15
==============

- fix: Splunk Cloud vetting refused due to https protocol verification checking if the URI contains https rather than starts with https
- fix: JIRA dedup feature might under some systems be generating a different hash for the same issue due to a different order of the json data after json load operation in Python, perform the md5 calculation before calling json load

Version 1.0.14
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
