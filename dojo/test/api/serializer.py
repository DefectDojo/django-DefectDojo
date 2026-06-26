from django.conf import settings
from rest_framework import serializers

from dojo.models import (
    Engagement,
    Notes,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
    Test_Type,
)


class TestSerializer(serializers.ModelSerializer):
    test_type_name = serializers.ReadOnlyField()

    class Meta:
        model = Test
        exclude = ("inherited_tags",)

    def get_fields(self):
        from dojo.api_v2.serializers import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            TagListSerializerField,
        )
        from dojo.finding.api.serializer import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            FindingGroupSerializer,
        )
        fields = super().get_fields()
        fields["tags"] = TagListSerializerField(required=False)
        fields["finding_groups"] = FindingGroupSerializer(
            source="finding_group_set", many=True, read_only=True,
        )
        return fields

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


class TestCreateSerializer(serializers.ModelSerializer):
    engagement = serializers.PrimaryKeyRelatedField(
        queryset=Engagement.objects.all(),
    )
    notes = serializers.PrimaryKeyRelatedField(
        allow_null=True,
        queryset=Notes.objects.all(),
        many=True,
        required=False,
    )

    class Meta:
        model = Test
        exclude = ("inherited_tags",)

    def get_fields(self):
        from dojo.api_v2.serializers import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            TagListSerializerField,
        )
        fields = super().get_fields()
        fields["tags"] = TagListSerializerField(required=False)
        return fields


class TestTypeCreateSerializer(serializers.ModelSerializer):

    class Meta:
        model = Test_Type
        exclude = ("dynamically_generated",)


class TestTypeSerializer(serializers.ModelSerializer):
    name = serializers.ReadOnlyField()

    class Meta:
        model = Test_Type
        exclude = ("dynamically_generated",)


class TestToNotesSerializer(serializers.Serializer):
    test_id = serializers.PrimaryKeyRelatedField(
        queryset=Test.objects.all(), many=False, allow_null=True,
    )

    def get_fields(self):
        from dojo.api_v2.serializers import NoteSerializer  # noqa: PLC0415 -- lazy import, avoids circular dependency
        fields = super().get_fields()
        fields["notes"] = NoteSerializer(many=True)
        return fields


class TestToFilesSerializer(serializers.Serializer):
    test_id = serializers.PrimaryKeyRelatedField(
        queryset=Test.objects.all(), many=False, allow_null=True,
    )

    def get_fields(self):
        from dojo.api_v2.serializers import FileSerializer  # noqa: PLC0415 -- lazy import, avoids circular dependency
        fields = super().get_fields()
        fields["files"] = FileSerializer(many=True)
        return fields

    def to_representation(self, data):
        test = data.get("test_id")
        files = data.get("files")
        new_files = [{
                "id": file.id,
                "file": f"{settings.SITE_URL}/{file.get_accessible_url(test, test.id)}",
                "title": file.title,
            } for file in files]
        return {"test_id": test.id, "files": new_files}


class TestImportFindingActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Test_Import_Finding_Action
        fields = "__all__"


class TestImportSerializer(serializers.ModelSerializer):
    # findings = TestImportFindingActionSerializer(source='test_import_finding_action', many=True, read_only=True)
    test_import_finding_action_set = TestImportFindingActionSerializer(
        many=True, read_only=True,
    )

    class Meta:
        model = Test_Import
        fields = "__all__"
