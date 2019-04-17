from django import template
from django.utils.safestring import mark_safe

register = template.Library()


@register.tag(name='as')
def do_as(parser, token):
    """Stores the content between as and endas in the variable whose
    name is passed to the as tag.."""

    try:
        tag_name, var_name = token.split_contents()
    except ValueError:
        raise template.TemplateSyntaxError(
            "%r tag requires a single argument" % token.contents.split()[0]
        )
    nodelist = parser.parse(('endas',))
    parser.delete_first_token()
    return AsNode(var_name, nodelist)


class AsNode(template.Node):
    def __init__(self, var_name, nodelist):
        self.var_name = var_name
        self.nodelist = nodelist

    def render(self, context):
        context[self.var_name] = mark_safe(self.nodelist.render(context))
        return ''
