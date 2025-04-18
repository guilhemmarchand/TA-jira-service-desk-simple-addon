[jira_service_desk]
param._cam = <json> Adaptive Response parameters.
param.account = <list> Select JIRA Account. It's a required parameter.
param.jira_project = <list> Project. It's a required parameter.
param.jira_issue_type = <list> Issue Type. It's a required parameter.
param.jira_priority = <list> Priority.
param.jira_priority_dynamic = <string> Dynamic Priority.
param.jira_summary = <string> Summary. It's a required parameter.
param.jira_description = <string> Description. It's a required parameter.
param.jira_auto_close = <list> Auto close issue:. It's a required parameter. It's default value is enabled.
param.jira_auto_close_key_value_pair = <string> Auto close key value pair.
param.jira_auto_close_status_transition_value = <string> Auto close status transition value.
param.jira_auto_close_status_transition_comment = <string> Auto close status transition comment.
param.jira_auto_close_issue_number_field_name = <string> Auto close issue number field name.
param.jira_assignee = <string> Assignee.
param.jira_reporter = <string> Reporter.
param.jira_labels = <string> Labels.
param.jira_components = <string> Components names.
param.jira_dedup = <list> JIRA dedup behaviour:. It's a required parameter. It's default value is disabled.
param.jira_dedup_comment = <string> JIRA dedup comment.
param.jira_dedup_exclude_statuses = <string> JIRA dedup excluded statuses.
param.jira_dedup_content = <string> JIRA dedup content.
param.jira_attachment = <list> Results attachment:. It's a required parameter. It's default value is disabled.
param.jira_results_description = <list> Add results to description:. It's a required parameter. It's default value is disabled.
param.jira_attachment_token = <string> Attachment token.
param.jira_customfields = <string> custom fields structure.

[jira_service_desk_replay]
param.account = <list> Select Account. It's a required parameter.
param.ticket_uuid = <string> Ticket uuid.
param.ticket_data = <string> Ticket data.
param.ticket_status = <string> Ticket status.
param.ticket_no_attempts = <string> Ticket number of attempts.
param.ticket_max_attempts = <string> Ticket max number of attempts.
param.ticket_ctime = <string> Ticket creation time.
param.ticket_mtime = <string> Ticket modification time.
