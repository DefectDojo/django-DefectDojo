import base64
from itertools import izip, chain

import re
from django import template
from django.contrib.contenttypes.models import ContentType
from django.template.defaultfilters import stringfilter
from django.utils.html import escape
from django.utils.safestring import mark_safe, SafeData
from django.utils.text import normalize_newlines

from dojo.models import Check_List, BurpRawRequestResponse

register = template.Library()


@register.filter(name='ports_open')
def ports_open(value):
    count = 0
    for ipscan in value.ipscan_set.all():
        count += len(eval(ipscan.services))
    return count


@register.filter(name='checklist_status')
def checklist_status(value):
    return Check_List.get_status(value)


@register.filter(is_safe=True, needs_autoescape=True)
@stringfilter
def linebreaksasciidocbr(value, autoescape=None):
    """
    Converts all newlines in a piece of plain text to HTML line breaks
    (``+ <br />``).
    """
    autoescape = autoescape and not isinstance(value, SafeData)
    value = normalize_newlines(value)
    if autoescape:
        value = escape(value)

    return mark_safe(value.replace('\n', '&nbsp;+<br />'))

@register.simple_tag
def dojo_version():
    from dojo.settings import VERSION
    return 'v. ' + VERSION

@register.filter
def content_type(obj):
    if not obj:
        return False
    return ContentType.objects.get_for_model(obj).id


@register.filter
def content_type_str(obj):
    if not obj:
        return False
    return ContentType.objects.get_for_model(obj)


@register.filter(is_safe=True, needs_autoescape=False)
@stringfilter
def action_log_entry(value, autoescape=None):
    import json
    history = json.loads(value)
    text = ''
    for k in history.iterkeys():
        text += k.capitalize() + ' changed from "' + history[k][0] + '" to "' + history[k][1] + '"<br/>'

    return mark_safe(text)


@register.simple_tag(takes_context=True)
def dojo_body_class(context):
    request = context['request']
    return request.COOKIES.get('dojo-sidebar', 'min')


@register.simple_tag
def random_value():
    import string
    import random
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))


@register.tag
def colgroup(parser, token):
    """
    Usage:: {% colgroup items into 3 cols as grouped_items %}

    <table border="0">
        {% for row in grouped_items %}
        <tr>
            {% for item in row %}
            <td>{% if item %}{{ forloop.parentloop.counter }}. {{ item }}{% endif %}</td>
            {% endfor %}
        </tr>
        {% endfor %}
    </table>

    Outputs::
    ============================================
    | 1. One   | 1. Eleven   | 1. Twenty One   |
    | 2. Two   | 2. Twelve   | 2. Twenty Two   |
    | 3. Three | 3. Thirteen | 3. Twenty Three |
    | 4. Four  | 4. Fourteen |                 |
    ============================================
    """
    class Node(template.Node):
        def __init__(self, iterable, num_cols, varname):
            self.iterable = iterable
            self.num_cols = num_cols
            self.varname = varname

        def render(self, context):
            iterable = template.Variable(self.iterable).resolve(context)
            num_cols = self.num_cols
            context[self.varname] = izip(*[chain(iterable, [None]*(num_cols-1))] * num_cols)
            return u''

    try:
        _, iterable, _, num_cols, _, _, varname = token.split_contents()
        num_cols = int(num_cols)
    except ValueError:
        raise template.TemplateSyntaxError("Invalid arguments passed to %r." % token.contents.split()[0])
    return Node(iterable, num_cols, varname)
