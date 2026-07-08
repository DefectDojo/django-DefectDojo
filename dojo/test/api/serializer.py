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
    # Effective finding-matching policy for this test, resolved from the
    # per-scanner settings (DEDUPLICATION_ALGORITHM_PER_PARSER /
    # HASHCODE_FIELDS_PER_SCANNER). Read-only: surfaced so users can see
    # which algorithm and fields deduplication and reimport matching use,
    # instead of having to ask support or read settings.dist.py.
    # Typed fields (not ReadOnlyField) so drf-spectacular can emit an exact schema.
    deduplication_algorithm = serializers.CharField(
        read_only=True,
        help_text="Algorithm used to match findings for deduplication and reimport "
                  "(legacy, unique_id_from_tool, hash_code, or unique_id_from_tool_or_hash_code).")
    hash_code_fields = serializers.ListField(
        child=serializers.CharField(),
        read_only=True,
        allow_null=True,
        help_text="Finding fields hashed to compute hash_code for this test's scan type. "
                  "Null when the scan type has no per-scanner configuration and legacy "
                  "default fields are used.")

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
