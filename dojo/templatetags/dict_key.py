from django.template.defaultfilters import register


@register.filter(name='dict_key')
def dict_key(d, key):
    return d.get(key)
