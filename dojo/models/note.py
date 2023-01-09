from django.db import models
from ..utils import get_current_datetime


class Note_Type(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=200)
    is_single = models.BooleanField(default=False, null=False)
    is_active = models.BooleanField(default=True, null=False)
    is_mandatory = models.BooleanField(default=True, null=False)

    def __str__(self):
        return self.name


class NoteHistory(models.Model):
    note_type = models.ForeignKey(Note_Type, null=True, blank=True, on_delete=models.CASCADE)
    data = models.TextField()
    time = models.DateTimeField(null=True, editable=False,
                                default=get_current_datetime)
    current_editor = models.ForeignKey('Dojo_User', editable=False, null=True, on_delete=models.CASCADE)

    def copy(self):
        copy = self
        copy.pk = None
        copy.id = None
        copy.save()
        return copy


class Notes(models.Model):
    note_type = models.ForeignKey(Note_Type, related_name='note_type', null=True, blank=True, on_delete=models.CASCADE)
    entry = models.TextField()
    date = models.DateTimeField(null=False, editable=False,
                                default=get_current_datetime)
    author = models.ForeignKey('Dojo_User', related_name='editor_notes_set', editable=False, on_delete=models.CASCADE)
    private = models.BooleanField(default=False)
    edited = models.BooleanField(default=False)
    editor = models.ForeignKey('Dojo_User', related_name='author_notes_set', editable=False, null=True, on_delete=models.CASCADE)
    edit_time = models.DateTimeField(null=True, editable=False,
                                default=get_current_datetime)
    history = models.ManyToManyField(NoteHistory, blank=True,
                                   editable=False)

    class Meta:
        ordering = ['-date']

    def __str__(self):
        return self.entry

    def copy(self):
        copy = self
        # Save the necessary ManyToMany relationships
        old_history = list(self.history.all())
        # Wipe the IDs of the new object
        copy.pk = None
        copy.id = None
        # Save the object before setting any ManyToMany relationships
        copy.save()
        # Copy the history
        for history in old_history:
            copy.history.add(history.copy())

        return copy
