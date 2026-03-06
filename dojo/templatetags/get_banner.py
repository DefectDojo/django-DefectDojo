import nh3
from django import template
from django.utils.safestring import mark_safe

from dojo.models import BannerConf
from dojo.templatetags.display_tags import _NH3_ALLOWED_ATTRIBUTES, _NH3_ALLOWED_TAGS

register = template.Library()


@register.filter
def get_banner_conf(attribute):
    try:
        banner_config = BannerConf.objects.get()
        value = getattr(banner_config, attribute, None)
        if value:
            if attribute == "banner_message":
                # only admin can edit login banner, so we allow html, but still sanitize it
                return mark_safe(nh3.clean(value, tags=_NH3_ALLOWED_TAGS, attributes=_NH3_ALLOWED_ATTRIBUTES))
            return value
    except Exception:
        return False
    return False
