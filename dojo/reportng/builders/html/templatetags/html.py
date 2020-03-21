from django.template import Library

from dojo.templatetags.display_tags import markdown_render


register = Library()

register.filter(markdown_render)
