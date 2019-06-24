from django import template
register = template.Library()


@register.filter(name='get_public_notes')
def get_public_notes(notes):
    return notes.filter(private=False)
