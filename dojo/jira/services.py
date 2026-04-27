"""
Service layer for Jira integration.

Core code imports from here instead of from dojo.jira.helper directly so that
the helper module (which imports dojo.forms/models/utils) can be loaded
lazily, breaking the import cycle.
"""

import logging

logger = logging.getLogger(__name__)


def _get_helper():
    from dojo.jira import helper  # noqa: PLC0415 — lazy to break import cycle with dojo.forms
    return helper


# ---------------------------------------------------------------------------
# Mutation wrappers — delegate to dojo.jira.helper
# ---------------------------------------------------------------------------

def push(obj, *args, **kwargs):
    """
    Push a finding, finding group, or engagement to Jira.

    Wraps: jira_helper.push_to_jira
    """
    return _get_helper().push_to_jira(obj, *args, **kwargs)


def add_comment(obj, note, *, force_push=False, **kwargs):
    """
    Add a comment to a Jira issue.

    Wraps: jira_helper.add_comment
    """
    return _get_helper().add_comment(obj, note, force_push=force_push, **kwargs)


def add_simple_comment(jira_instance, jira_issue, comment):
    """
    Add a simple text comment to a Jira issue.

    Wraps: jira_helper.add_simple_jira_comment
    """
    return _get_helper().add_simple_jira_comment(jira_instance, jira_issue, comment)


def add_comment_internal(jira_issue_id, note_id, *, force_push=False, **kwargs):
    """
    Internal add comment by IDs.

    Wraps: jira_helper.add_comment_internal
    """
    return _get_helper().add_comment_internal(jira_issue_id, note_id, force_push=force_push, **kwargs)


def get_epic_task(task_name):
    """
    Return the raw Celery task for epic operations.

    Use with dojo_dispatch_task() when you need Celery task semantics.
    """
    return getattr(_get_helper(), task_name, None)


def add_epic(engagement_id, **kwargs):
    """
    Create a Jira epic for an engagement.

    Wraps: jira_helper.add_epic
    """
    return _get_helper().add_epic(engagement_id, **kwargs)


def update_epic(engagement_id, **kwargs):
    """
    Update a Jira epic for an engagement.

    Wraps: jira_helper.update_epic
    """
    return _get_helper().update_epic(engagement_id, **kwargs)


def close_epic(engagement_id, push_to_jira, **kwargs):
    """
    Close a Jira epic for an engagement.

    Wraps: jira_helper.close_epic
    """
    return _get_helper().close_epic(engagement_id, push_to_jira, **kwargs)


def link_finding(request, finding, new_jira_issue_key):
    """
    Link a finding to an existing Jira issue.

    Wraps: jira_helper.finding_link_jira
    """
    return _get_helper().finding_link_jira(request, finding, new_jira_issue_key)


def unlink_finding(request, finding):
    """
    Unlink a finding from its Jira issue.

    Wraps: jira_helper.finding_unlink_jira
    """
    return _get_helper().finding_unlink_jira(request, finding)


def link_finding_group(request, finding_group, new_jira_issue_key):
    """
    Link a finding group to an existing Jira issue.

    Wraps: jira_helper.finding_group_link_jira
    """
    return _get_helper().finding_group_link_jira(request, finding_group, new_jira_issue_key)


def unlink(request, obj):
    """
    Unlink an object from its Jira issue.

    Wraps: jira_helper.unlink_jira
    """
    return _get_helper().unlink_jira(request, obj)


def push_status(obj, jira_instance, jira, issue, *, save=False):
    """
    Push finding status to Jira.

    Wraps: jira_helper.push_status_to_jira
    """
    return _get_helper().push_status_to_jira(obj, jira_instance, jira, issue, save=save)


def update_issue(obj, *args, **kwargs):
    """
    Update a Jira issue.

    Wraps: jira_helper.update_jira_issue
    """
    return _get_helper().update_jira_issue(obj, *args, **kwargs)


def process_project_form(request, instance=None, target=None, product=None, engagement=None):
    """
    Process a Jira project configuration form.

    Wraps: jira_helper.process_jira_project_form
    """
    return _get_helper().process_jira_project_form(request, instance=instance, target=target,
                                                    product=product, engagement=engagement)


def process_epic_form(request, engagement=None):
    """
    Process a Jira epic form.

    Wraps: jira_helper.process_jira_epic_form
    """
    return _get_helper().process_jira_epic_form(request, engagement=engagement)


def process_resolution_from_jira(finding, resolution_id, resolution_name,
                                 assignee_name, jira_now, jira_issue,
                                 finding_group=None):
    """
    Process a resolution change from Jira webhook.

    Wraps: jira_helper.process_resolution_from_jira
    """
    return _get_helper().process_resolution_from_jira(
        finding, resolution_id, resolution_name,
        assignee_name, jira_now, jira_issue,
        finding_group=finding_group,
    )


# ---------------------------------------------------------------------------
# Query wrappers
# ---------------------------------------------------------------------------

def is_enabled():
    """
    Check if Jira integration is enabled globally.

    Wraps: jira_helper.is_jira_enabled
    """
    return _get_helper().is_jira_enabled()


def is_configured_and_enabled(obj):
    """
    Check if Jira is configured and enabled for the given object.

    Wraps: jira_helper.is_jira_configured_and_enabled
    """
    return _get_helper().is_jira_configured_and_enabled(obj)


def has_issue(obj):
    """
    Check if the object has a linked Jira issue.

    Wraps: jira_helper.has_jira_issue
    """
    return _get_helper().has_jira_issue(obj)


def has_configured(obj):
    """
    Check if Jira is configured for the given object.

    Wraps: jira_helper.has_jira_configured
    """
    return _get_helper().has_jira_configured(obj)


def get_project(obj, *, use_inheritance=True, jira_enabled=False):
    """
    Get the Jira project configuration for an object.

    Wraps: jira_helper.get_jira_project
    """
    return _get_helper().get_jira_project(obj, use_inheritance=use_inheritance, jira_enabled=jira_enabled)


def get_instance(obj, *, jira_enabled=False):
    """
    Get the Jira instance for an object.

    Wraps: jira_helper.get_jira_instance
    """
    return _get_helper().get_jira_instance(obj, jira_enabled=jira_enabled)


def get_issue(obj):
    """
    Get the local JIRA_Issue record for an object.

    Wraps: jira_helper.get_jira_issue
    """
    return _get_helper().get_jira_issue(obj)


def get_url(obj):
    """
    Get the Jira URL for an object.

    Wraps: jira_helper.get_jira_url
    """
    return _get_helper().get_jira_url(obj)


def get_issue_url(issue):
    """
    Get the URL for a specific Jira issue.

    Wraps: jira_helper.get_jira_issue_url
    """
    return _get_helper().get_jira_issue_url(issue)


def get_project_url(obj):
    """
    Get the Jira project URL for an object.

    Wraps: jira_helper.get_jira_project_url
    """
    return _get_helper().get_jira_project_url(obj)


def get_key(obj):
    """
    Get the Jira issue key for an object.

    Wraps: jira_helper.get_jira_key
    """
    return _get_helper().get_jira_key(obj)


def get_issue_key(obj):
    """
    Get the Jira issue key.

    Wraps: jira_helper.get_jira_issue_key
    """
    return _get_helper().get_jira_issue_key(obj)


def get_project_key(obj):
    """
    Get the Jira project key.

    Wraps: jira_helper.get_jira_project_key
    """
    return _get_helper().get_jira_project_key(obj)


def get_creation(obj):
    """
    Get the Jira issue creation datetime.

    Wraps: jira_helper.get_jira_creation
    """
    return _get_helper().get_jira_creation(obj)


def get_change(obj):
    """
    Get the Jira issue last-changed datetime.

    Wraps: jira_helper.get_jira_change
    """
    return _get_helper().get_jira_change(obj)


def is_push_all_issues(instance):
    """
    Check if push_all_issues is enabled.

    Wraps: jira_helper.is_push_all_issues
    """
    return _get_helper().is_push_all_issues(instance)


def is_keep_in_sync(obj, prefetched_jira_instance=None):
    """
    Check if object should be kept in sync with Jira.

    Wraps: jira_helper.is_keep_in_sync_with_jira
    """
    return _get_helper().is_keep_in_sync_with_jira(obj, prefetched_jira_instance=prefetched_jira_instance)


def is_push(instance, push_to_jira_parameter=None):
    """
    Check if Jira push should happen.

    Wraps: jira_helper.is_push_to_jira
    """
    return _get_helper().is_push_to_jira(instance, push_to_jira_parameter=push_to_jira_parameter)


def can_be_pushed(obj, form=None):
    """
    Check if an object can be pushed to Jira.

    Returns (can_push, reason, error_code).
    Wraps: jira_helper.can_be_pushed_to_jira
    """
    return _get_helper().can_be_pushed_to_jira(obj, form=form)


def escape_text(text):
    """
    Escape text for Jira formatting.

    Wraps: jira_helper.escape_for_jira
    """
    return _get_helper().escape_for_jira(text)


def already_linked(finding, jira_issue_key, jira_id):
    """
    Check if a finding is already linked to a Jira issue.

    Wraps: jira_helper.jira_already_linked
    """
    return _get_helper().jira_already_linked(finding, jira_issue_key, jira_id)


def get_qualified_findings(finding_group):
    """
    Get findings in a group that qualify for Jira.

    Wraps: jira_helper.get_qualified_findings
    """
    return _get_helper().get_qualified_findings(finding_group)


def get_non_qualified_findings(finding_group):
    """
    Get findings in a group that don't qualify for Jira.

    Wraps: jira_helper.get_non_qualified_findings
    """
    return _get_helper().get_non_qualified_findings(finding_group)


def get_sla_deadline(obj):
    """
    Get the SLA deadline for a Jira issue.

    Wraps: jira_helper.get_sla_deadline
    """
    return _get_helper().get_sla_deadline(obj)


def get_severity(findings):
    """
    Get the severity for a set of findings (Jira context).

    Wraps: jira_helper.get_severity
    """
    return _get_helper().get_severity(findings)


def get_connection(obj):
    """
    Get a Jira connection for the given object.

    Wraps: jira_helper.get_jira_connection
    """
    return _get_helper().get_jira_connection(obj)


def get_connection_raw(jira_server, jira_username, jira_password):
    """
    Get a raw Jira connection.

    Wraps: jira_helper.get_jira_connection_raw
    """
    return _get_helper().get_jira_connection_raw(jira_server, jira_username, jira_password)


def get_issue_from_jira(find):
    """
    Fetch a Jira issue from the Jira server.

    Wraps: jira_helper.get_jira_issue_from_jira
    """
    return _get_helper().get_jira_issue_from_jira(find)


def issue_from_jira_is_active(issue_from_jira):
    """
    Check if a Jira issue is in an active state.

    Wraps: jira_helper.issue_from_jira_is_active
    """
    return _get_helper().issue_from_jira_is_active(issue_from_jira)


def jira_get_issue(jira_project, issue_key):
    """
    Get a Jira issue by project and key.

    Wraps: jira_helper.jira_get_issue
    """
    return _get_helper().jira_get_issue(jira_project, issue_key)


# ---------------------------------------------------------------------------
# Logging wrappers
# ---------------------------------------------------------------------------

def log_cannot_be_pushed_reason(error, obj):
    """
    Log the reason an object cannot be pushed to Jira.

    Wraps: jira_helper.log_jira_cannot_be_pushed_reason
    """
    _get_helper().log_jira_cannot_be_pushed_reason(error, obj)


def log_message(text, finding):
    """
    Log a Jira-related message.

    Wraps: jira_helper.log_jira_message
    """
    _get_helper().log_jira_message(text, finding)
