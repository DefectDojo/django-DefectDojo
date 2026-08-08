from rest_framework import serializers

from dojo.note_type.models import Note_Type


class NoteTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note_Type
        fields = "__all__"
