from django import template

register = template.Library()


@register.filter(name="get_notetype_notes_count")
def get_notetype_notes_count(notes):
    notes_without_type = notes.filter(note_type=None).count()
    notes_count = notes.count()
    return notes_count - notes_without_type
