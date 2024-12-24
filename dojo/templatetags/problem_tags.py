from dojo.models import Finding

from django import template
from django.conf import settings

register = template.Library()

@register.filter
def count_distinct_script_ids(findings):
    return len(set(finding.vuln_id_from_tool for finding in findings))

@register.filter
def check_problems_enabled(value):
    return settings.PROBLEM_MAPPINGS_JSON_URL