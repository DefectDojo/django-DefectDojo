import json

from django import template
from django.utils.safestring import mark_safe

register = template.Library()


@register.filter
def as_json(value):
    return json.dumps(value)


@register.filter(is_safe=True)
def as_json_no_html_esc(value):
    return mark_safe(json.dumps(value))
