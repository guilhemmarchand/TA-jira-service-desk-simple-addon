
[jira_service_desk]
python.version = python3
param.jira_issue_type = <string> Issue type. It's a required parameter.
param.jira_labels = <string> Labels.
param.jira_assignee = <string> Jira assignee.
param.jira_description = <string> Description.
param.jira_summary = <string> Summary. It's a required parameter.
param._cam = <json> Active response parameters.
param.jira_priority = <string> Priority. It's a required parameter.
param.jira_priority_dynamic = <string> Priority override from results, optional.
param.jira_project = <list> Project. It's a required parameter.
param.jira_components = <string> JIRA components fields structure, optional.
param.jira_customfields = <string> JIRA custom fields structure, optional.
param.jira_customfields_parsing = <boolean> enable or disable parsing of the custom fields, optional.
param.jira_dedup = <string> JIRA deduplication behaviour, optional.
param.jira_dedup_exclude_statuses = <string> list of JIRA statuses that will not be considered for comment updates, optional.
param.jira_dedup_content = <string> restricted scope for dedup MD5 sum calculation
param.jira_attachment = <string> Attach Splunk results to the JIRA issue, optional.
param.jira_attachment_token = <string> Attach Splunk results to the JIRA issue (token), optional.

[jira_service_desk_replay]
python.version = python3
param.ticket_uuid = <string> UUID value stored in the KVstore.
param.ticket_data = <string> JSON object stored in the KVstore.
param.ticket_status = <string> Status stored in the KVstore.
param.ticket_no_attempts = <string> Number of attempts stored in the KVstore.
param.ticket_max_attempts = <string> Maximal number of attempts.
param.ticket_ctime = <string> Creation time stored in the KVstore.
param.ticket_mtime = <string> Modification time stored in the KVstore.
