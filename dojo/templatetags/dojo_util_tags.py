import uuid

from django import template
from django.db.models import Model
from django.utils.safestring import mark_safe

from ..models_base import get_perm


register = template.Library()


@register.filter(name="addstr", is_safe=True)
def do_addstr(value, arg):
    """Concatenates two values after coercing them to str."""
    return str(value) + str(arg)


@register.filter(name="if_unset")
def do_if_unset(value, arg):
    """If value is None or the empty string, it returns the default, else value.

    This is useful for providing a default for an undefined variable.
    """
    return arg if value in (None, "") else value


@register.filter(name="model_name")
def do_model_name(value):
    """Returns the model name of a model or model instance."""
    if isinstance(value, Model) or isinstance(value, type) and issubclass(value, Model):
        return value._meta.model_name
    raise TypeError("%r is neither a model nor a model instance" % value)


@register.filter(name="get_perm", is_safe=True)
def do_get_perm(obj, perm_type):
    """Returns the name of a specific permission.

    The arguments are passed directly to dojo.models_base.get_perm().
    """
    return get_perm(perm_type, obj)


@register.filter(name="strip", is_safe=True)
def do_strip(value):
    """Strips leading and trailing whitespace using str.strip()."""
    return value.strip()


@register.tag(name="as")
def do_as(parser, token):
    """Stores the content between as and endas in a named variable."""

    try:
        tag_name, var_name = token.split_contents()
    except ValueError:
        raise template.TemplateSyntaxError(
            "{!r} tag requires a single argument".format(token.contents.split()[0])
        )
    nodelist = parser.parse(("endas",))
    parser.delete_first_token()
    return AsNode(var_name, nodelist)


@register.simple_tag(name="uuid")
def do_uuid():
    """Inserts a random UUID4, e.g. for creating HTML IDs dynamically."""
    return str(uuid.uuid4())


class AsNode(template.Node):
    def __init__(self, var_name, nodelist):
        self.var_name = var_name
        self.nodelist = nodelist

    def render(self, context):
        context[self.var_name] = mark_safe(self.nodelist.render(context))
        return ""
