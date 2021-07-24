
[jira_service_desk]
param._cam = <json> Active response parameters.
param.account = <list> Select JIRA Account. It's a required parameter.
param.jira_project = <list> Project. It's a required parameter.
param.jira_issue_type = <list> Issue Type. It's a required parameter.
param.jira_priority = <list> Priority. It's a required parameter.
param.jira_priority_dynamic = <string> Dynamic Priority.
param.jira_summary = <string> Summary. It's a required parameter.
param.jira_description = <string> Description. It's a required parameter.
param.jira_assignee = <string> Assignee.
param.jira_reporter = <string> Reporter.
param.jira_labels = <string> Labels.
param.jira_components = <string> Components names.
param.jira_dedup = <list> JIRA dedup behaviour:. It's a required parameter. It's default value is disabled.
param.jira_dedup_exclude_statuses = <string> JIRA dedup excluded statuses.
param.jira_dedup_content = <string> JIRA dedup content.
param.jira_attachment = <list> Results attachment:. It's a required parameter. It's default value is disabled.
param.jira_attachment_token = <string> Attachment token.
param.jira_customfields = <string> custom fields structure.
param.jira_customfields_parsing = <list> Custom fields parsing:. It's a required parameter. It's default value is enabled.

[jira_service_desk_replay]
param.account = <list> Select Account. It's a required parameter.
param.ticket_uuid = <string> Ticket uuid.
param.ticket_data = <string> Ticket data.
param.ticket_status = <string> Ticket status.
param.ticket_no_attempts = <string> Ticket number of attempts.
param.ticket_max_attempts = <string> Ticket max number of attempts.
param.ticket_ctime = <string> Ticket creation time.
param.ticket_mtime = <string> Ticket modification time.

