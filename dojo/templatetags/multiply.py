from django import template

register = template.Library()


@register.filter
def multiply(value, arg):  # noqa: FURB118
    return value * arg
