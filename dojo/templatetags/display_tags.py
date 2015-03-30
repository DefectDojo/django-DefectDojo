from django import template
from dojo.models import Check_List

register = template.Library()


@register.filter(name='ports_open')
def ports_open(value):
    count = 0
    for ipscan in value.ipscan_set.all():
        count += len(eval(ipscan.services))
    return count


@register.filter(name='checklist_status')
def checklist_status(value):
    return Check_List.get_status(value)
