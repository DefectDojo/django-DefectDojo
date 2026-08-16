from django import template

from dojo.notes.helper import visible_notes

register = template.Library()


@register.filter(name="get_public_notes")
def get_public_notes(notes):
    if notes:
        return notes.filter(private=False)
    return None


@register.filter(name="visible_to")
def visible_to(notes, user):
    """The notes ``user`` may see. For templates that read the relation directly."""
    return visible_notes(notes, user)
