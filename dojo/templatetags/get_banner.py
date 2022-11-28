from django.utils.safestring import mark_safe
import bleach
from bleach.css_sanitizer import CSSSanitizer
from django import template
from dojo.models import BannerConf

register = template.Library()


@register.filter
def get_banner_conf(attribute):
    try:
        banner_config = BannerConf.objects.get()
        value = getattr(banner_config, attribute, None)
        if value:
            if attribute == 'banner_message':
                # only admin can edit login banner, so we allow html, but still bleach it
                allowed_attributes = bleach.ALLOWED_ATTRIBUTES
                allowed_attributes['a'] = allowed_attributes['a'] + ['style', 'target']
                return mark_safe(bleach.clean(
                    value,
                    attributes=allowed_attributes,
                    css_sanitizer=CSSSanitizer(allowed_css_properties=['color', 'font-weight'])))
            else:
                return value
        else:
            return False
    except Exception:
        return False
