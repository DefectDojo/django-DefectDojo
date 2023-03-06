from django.utils.safestring import mark_safe
import bleach
from bleach.css_sanitizer import CSSSanitizer
from django import template

register = template.Library()


@register.filter
def bleach_announcement_message(message):
    allowed_attributes = bleach.ALLOWED_ATTRIBUTES
    allowed_attributes['a'] = allowed_attributes['a'] + ['style', 'target']
    return mark_safe(bleach.clean(
        message,
        attributes=allowed_attributes,
        css_sanitizer=CSSSanitizer(allowed_css_properties=['color', 'font-weight'])))
