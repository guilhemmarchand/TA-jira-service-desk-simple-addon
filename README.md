# JIRA Service Desk simple addon

| branch | build status |
| ---    | ---          |
| master | [![master status](https://circleci.com/gh/guilhemmarchand/TA-jira-service-desk-simple-addon/tree/master.svg?style=svg)](https://circleci.com/gh/guilhemmarchand/TA-jira-service-desk-simple-addon/tree/master)

## The Splunk Add-on for JIRA Atlassian Service Desk provides alerts action for JIRA issues creation:

- Trigger JIRA issue creation from Splunk core alerts and Enterprise Security correlation searches
- Dynamic retrieval per JIRA project for types of issues and priority
- Dynamic assignment of priority (optional)
- Dynamic and/or static assignment of summary, description, assignee and labels
- Custom fields full capabilities via the embedded custom field structure in alerts (optional)
- Resilient store JIRA issue creation, shall a JIRA issue fails to be created, the resilient workflow handles automatic retries with a resilient policy
- Monitoring of JIRA issue workflow via the embedded Overview dashboard and out of the box alerts

![screenshot](./docs/img/screenshot.png)

See the online documentation: https://ta-jira-service-desk-simple-addon.readthedocs.io/en/latest/
