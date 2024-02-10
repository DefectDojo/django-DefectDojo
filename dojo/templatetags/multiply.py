from django import template

register = template.Library()

@register.filter
def multiply(value, arg):
    return value * arg