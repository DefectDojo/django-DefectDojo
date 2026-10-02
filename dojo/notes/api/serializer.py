from django.db import models
from django.utils import timezone
from rest_framework import serializers

from dojo.note_type.api.serializer import NoteTypeSerializer
from dojo.notes.helper import visible_notes
from dojo.notes.models import NoteHistory, Notes
from dojo.user.api.serializer import UserStubSerializer


class NoteHistorySerializer(serializers.ModelSerializer):
    current_editor = UserStubSerializer(read_only=True)
    note_type = NoteTypeSerializer(read_only=True, many=False)

    class Meta:
        model = NoteHistory
        fields = "__all__"


class VisibleNotesSerializer(serializers.ListSerializer):

    """Serialize only the notes the requester may see: non-private, or their own."""

    def to_representation(self, data):
        notes = data.all() if isinstance(data, models.Manager) else data
        user = getattr(self.context.get("request"), "user", None)
        return super().to_representation(visible_notes(notes, user))


class NoteSerializer(serializers.ModelSerializer):
    author = UserStubSerializer(many=False, read_only=True)
    editor = UserStubSerializer(read_only=True, many=False, allow_null=True)
    history = NoteHistorySerializer(read_only=True, many=True)
    note_type = NoteTypeSerializer(read_only=True, many=False)

    def update(self, instance, validated_data):
        # A partial (PATCH) update may omit "entry" entirely -- e.g. a body that
        # only carries read-only fields such as note_type. Previously this set
        # entry to None, blanking the note body, and then built a NoteHistory
        # with data=None, violating the NOT NULL constraint on
        # dojo_notehistory.data (HTTP 500). Only record an edit + history
        # revision when the body actually changes.
        new_entry = validated_data.get("entry", instance.entry)
        if "entry" not in validated_data or new_entry == instance.entry:
            instance.save()
            return instance
        instance.entry = new_entry
        instance.edited = True
        instance.editor = self.context["request"].user
        instance.edit_time = timezone.now()
        history = NoteHistory(
            data=instance.entry,
            time=instance.edit_time,
            current_editor=instance.editor,
        )
        history.save()
        instance.history.add(history)
        instance.save()
        return instance

    class Meta:
        model = Notes
        fields = "__all__"
        list_serializer_class = VisibleNotesSerializer
