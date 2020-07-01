from django import template
from dojo.models import Endpoint_Status
register = template.Library()


@register.filter(name='get_vulnerable_endpoints')
def get_vulnerable_endpoints(finding):
    status_list = finding.endpoint_status.all().filter(remediated=False)
    return [status.endpoint for status in status_list]


@register.filter(name='get_remediated_endpoints')
def get_remediated_endpoints(finding):
    status_list = finding.endpoint_status.all().filter(remediated=True)
    return [status.endpoint for status in status_list]


@register.filter
def endpoint_display_status(endpoint, finding):
    status = Endpoint_Status.objects.get(endpoint=endpoint, finding=finding)
    if status.false_positive:
        return "False Positive"
    if status.risk_accepted:
        return "Risk Accepted"
    if status.out_of_scope:
        return "Out of Scope"
    if status.remediated:
        return "Remediated"
    return "Active"


@register.filter
def endpoint_update_time(endpoint, finding):
    status = Endpoint_Status.objects.get(endpoint=endpoint, finding=finding)
    return status.last_modified


@register.filter
def endpoint_date(endpoint, finding):
    status = Endpoint_Status.objects.get(endpoint=endpoint, finding=finding)
    return status.date


@register.filter
def endpoint_remediator(endpoint, finding):
    status = Endpoint_Status.objects.get(endpoint=endpoint, finding=finding)
    return status.remediated_by


@register.filter
def endpoint_remediated_time(endpoint, finding):
    status = Endpoint_Status.objects.get(endpoint=endpoint, finding=finding)
    return status.remediated_time
