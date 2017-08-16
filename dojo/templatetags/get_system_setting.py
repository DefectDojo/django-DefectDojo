import re
from django import template
from dojo.models import System_Settings

register = template.Library()

@register.filter
def get_system_setting(system_setting):
    try:
        system_settings = System_Settings.objects.get()
        if getattr(system_settings, system_setting, None):
            return True
        else:
            return False
    except:
        return False