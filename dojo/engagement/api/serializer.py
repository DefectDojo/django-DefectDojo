from django.conf import settings
from rest_framework import serializers

from dojo.models import Check_List, Engagement, Engagement_Presets


class EngagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Engagement
        exclude = ("inherited_tags",)

    def get_fields(self):
        from dojo.api_v2.serializers import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            TagListSerializerField,
        )
        fields = super().get_fields()
        fields["tags"] = TagListSerializerField(required=False)
        return fields

    def validate(self, data):
        if self.context["request"].method == "POST":
            if data.get("target_start") > data.get("target_end"):
                msg = "Your target start date exceeds your target end date"
                raise serializers.ValidationError(msg)
        return data

    def build_relational_field(self, field_name, relation_info):
        from dojo.api_v2.serializers import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            FileSerializer,
            NoteSerializer,
        )
        if field_name == "notes":
            return NoteSerializer, {"many": True, "read_only": True}
        if field_name == "files":
            return FileSerializer, {"many": True, "read_only": True}
        return super().build_relational_field(field_name, relation_info)


class EngagementToNotesSerializer(serializers.Serializer):
    engagement_id = serializers.PrimaryKeyRelatedField(
        queryset=Engagement.objects.all(), many=False, allow_null=True,
    )

    def get_fields(self):
        from dojo.api_v2.serializers import NoteSerializer  # noqa: PLC0415 -- lazy import, avoids circular dependency
        fields = super().get_fields()
        fields["notes"] = NoteSerializer(many=True)
        return fields


class EngagementToFilesSerializer(serializers.Serializer):
    engagement_id = serializers.PrimaryKeyRelatedField(
        queryset=Engagement.objects.all(), many=False, allow_null=True,
    )

    def get_fields(self):
        from dojo.api_v2.serializers import FileSerializer  # noqa: PLC0415 -- lazy import, avoids circular dependency
        fields = super().get_fields()
        fields["files"] = FileSerializer(many=True)
        return fields

    def to_representation(self, data):
        engagement = data.get("engagement_id")
        files = data.get("files")
        new_files = [{
                "id": file.id,
                "file": "{site_url}/{file_access_url}".format(
                    site_url=settings.SITE_URL,
                    file_access_url=file.get_accessible_url(
                        engagement, engagement.id,
                    ),
                ),
                "title": file.title,
            } for file in files]
        return {"engagement_id": engagement.id, "files": new_files}


class EngagementCheckListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Check_List
        fields = "__all__"


class EngagementPresetsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Engagement_Presets
        fields = "__all__"
