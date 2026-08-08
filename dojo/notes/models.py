from django.db import models

from dojo.models import copy_model_util, get_current_datetime


class NoteHistory(models.Model):
    note_type = models.ForeignKey("dojo.Note_Type", null=True, blank=True, on_delete=models.CASCADE)
    data = models.TextField()
    time = models.DateTimeField(null=True, editable=False,
                                default=get_current_datetime)
    current_editor = models.ForeignKey("dojo.Dojo_User", editable=False, null=True, on_delete=models.CASCADE)

    def copy(self):
        copy = copy_model_util(self)
        copy.save()
        return copy


class Notes(models.Model):
    note_type = models.ForeignKey("dojo.Note_Type", related_name="note_type", null=True, blank=True, on_delete=models.CASCADE)
    entry = models.TextField()
    date = models.DateTimeField(null=False, editable=False,
                                default=get_current_datetime)
    author = models.ForeignKey("dojo.Dojo_User", related_name="editor_notes_set", editable=False, on_delete=models.CASCADE)
    private = models.BooleanField(default=False)
    edited = models.BooleanField(default=False)
    editor = models.ForeignKey("dojo.Dojo_User", related_name="author_notes_set", editable=False, null=True, on_delete=models.CASCADE)
    edit_time = models.DateTimeField(null=True, editable=False,
                                default=get_current_datetime)
    history = models.ManyToManyField("dojo.NoteHistory", blank=True,
                                   editable=False)

    class Meta:
        ordering = ["-date"]

    def __str__(self):
        return self.entry

    def copy(self):
        copy = copy_model_util(self)
        # Save the necessary ManyToMany relationships
        old_history = list(self.history.all())
        # Save the object before setting any ManyToMany relationships
        copy.save()
        # Copy the history
        for history in old_history:
            copy.history.add(history.copy())

        return copy
