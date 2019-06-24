from django import template
register = template.Library()


@register.filter(name='get_vulnerable_endpoints')
def get_vulnerable_endpoints(endpoints):
    return endpoints.filter(remediated=False)


@register.filter(name='get_remediated_endpoints')
def get_remediated_endpoints(endpoints):
    return endpoints.filter(remediated=True)
