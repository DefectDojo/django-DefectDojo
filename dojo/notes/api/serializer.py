from django.utils import timezone
from rest_framework import serializers

from dojo.note_type.api.serializer import NoteTypeSerializer
from dojo.notes.models import NoteHistory, Notes
from dojo.user.api.serializer import UserStubSerializer


class NoteHistorySerializer(serializers.ModelSerializer):
    current_editor = UserStubSerializer(read_only=True)
    note_type = NoteTypeSerializer(read_only=True, many=False)

    class Meta:
        model = NoteHistory
        fields = "__all__"


class NoteSerializer(serializers.ModelSerializer):
    author = UserStubSerializer(many=False, read_only=True)
    editor = UserStubSerializer(read_only=True, many=False, allow_null=True)
    history = NoteHistorySerializer(read_only=True, many=True)
    note_type = NoteTypeSerializer(read_only=True, many=False)

    def update(self, instance, validated_data):
        instance.entry = validated_data.get("entry")
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
