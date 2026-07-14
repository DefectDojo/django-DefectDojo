"""Template tags for grouping filter form fields by category."""
from collections import OrderedDict

from django import template

register = template.Library()

# Field-to-category mappings for the Finding filter forms.
# Fields not listed here fall into an "Other" catch-all group.
FINDING_FIELD_GROUPS = OrderedDict([
    ("Search", [
        "title", "component_name", "component_version",
        "vulnerability_id",
        "file_path", "unique_id_from_tool", "vuln_id_from_tool",
        "endpoints__host",
    ]),
    ("Severity & Risk", [
        "severity", "cwe", "epss_score", "epss_score_range",
        "epss_percentile", "epss_percentile_range",
        "outside_of_sla", "kev_date", "kev_before", "kev_after",
        "known_exploited", "ransomware_used",
    ]),
    ("Status", [
        "status", "active", "verified", "duplicate", "is_mitigated",
        "out_of_scope", "false_p",
        "fix_available", "risk_acceptance", "effort_for_fixing",
        "has_component", "has_notes", "has_finding_group", "has_tags",
        "location_status",
    ]),
    ("Dates", [
        "date", "on", "before", "after",
        "last_reviewed", "last_status_update",
        "mitigated", "mitigated_on", "mitigated_before", "mitigated_after",
        "planned_remediation_date", "planned_remediation_version",
    ]),
    ("Context", [
        "test__engagement__product__prod_type", "test__engagement__product",
        "test__engagement", "test", "test__test_type",
        "test__engagement__version", "test__version",
        "test__engagement__product__lifecycle",
        "reporter", "reviewers", "finding_group",
        "service", "param", "payload", "o",
    ]),
    ("Tags", [
        "tag", "tags", "tags_and",
        "test__tags", "test__tags_and",
        "test__engagement__tags", "test__engagement__tags_and",
        "test__engagement__product__tags", "test__engagement__product__tags_and",
        "not_tags", "not_test__tags",
        "not_test__engagement__tags", "not_test__engagement__product__tags",
    ]),
    ("Integrations", [
        "has_jira_issue", "jira_creation", "jira_change",
        "jira_issue__jira_key", "has_jira_group_issue",
        "has_any_jira_issue", "test_import_finding_action__test_import",
    ]),
])

# Categories that should be expanded by default
DEFAULT_OPEN_GROUPS = {"Search", "Severity & Risk", "Status"}

# Query param that django_filters' OrderingFilter uses for column sorting.
# Sorting is not filtering, so it must not auto-expand the filter panel.
ORDERING_PARAM = "o"


@register.filter
def has_active_filters(form):
    """
    Return True only if a real *filter* is applied to a bound filter form.

    Like Django's ``form.has_changed()`` but ignores the ordering field (``o``).
    Column-header sort links write ``?o=...`` into the same filter form, so
    plain ``has_changed`` treats sorting as filtering and auto-opens the filter
    panel even though the user only sorted a column. Ignoring ``o`` keeps the
    panel closed unless an actual filter value changed.
    """
    if form is None:
        return False
    return bool(set(form.changed_data) - {ORDERING_PARAM})


def _is_finding_filter(form):
    """Check if a form is a Finding-related filter."""
    class_name = type(form).__name__.lower()
    return "finding" in class_name


@register.simple_tag
def get_filter_groups(form):
    """
    Group a filter form's visible fields by category.

    Returns a list of dicts: [{"name": str, "fields": list, "open": bool}, ...]
    For non-Finding filters, returns all fields in a single "Filters" group.

    Usage:
        {% load filter_tags %}
        {% get_filter_groups form as filter_groups %}
        {% for group in filter_groups %}
            {{ group.name }} — {{ group.fields }}
        {% endfor %}
    """
    visible_fields = list(form.visible_fields())

    if not _is_finding_filter(form):
        return [{"name": "Filters", "fields": visible_fields, "open": True}]

    groups = FINDING_FIELD_GROUPS
    result = []
    assigned = set()

    for group_name, field_names in groups.items():
        group_fields = []
        for field in visible_fields:
            if field.name in field_names:
                group_fields.append(field)
                assigned.add(field.name)
        if group_fields:
            result.append({
                "name": group_name,
                "fields": group_fields,
                "open": group_name in DEFAULT_OPEN_GROUPS,
            })

    # Any remaining fields go to "Other"
    other_fields = [f for f in visible_fields if f.name not in assigned]
    if other_fields:
        result.append({
            "name": "Other",
            "fields": other_fields,
            "open": True,
        })

    return result
