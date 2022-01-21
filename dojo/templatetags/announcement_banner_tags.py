from django.utils.safestring import mark_safe
import bleach
from django import template

register = template.Library()


@register.filter
def bleach_announcement_message(message):
    allowed_attributes = bleach.ALLOWED_ATTRIBUTES
    allowed_attributes['a'] = allowed_attributes['a'] + ['style', 'target']
    return mark_safe(bleach.clean(message, attributes=allowed_attributes, styles=['color', 'font-weight']))
