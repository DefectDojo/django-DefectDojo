from dojo.models import Finding

from django import template

register = template.Library()

@register.filter
def count_unique_vulns(findings):
    return len(set(finding.vuln_id_from_tool for finding in findings))
