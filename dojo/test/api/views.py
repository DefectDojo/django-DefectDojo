from django.urls import reverse
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import DjangoModelPermissions, IsAuthenticated
from rest_framework.response import Response

from dojo.api_v2 import serializers as api_v2_serializers
from dojo.api_v2.views import PrefetchDojoModelViewSet, report_generate_response
from dojo.authorization import api_permissions as permissions
from dojo.models import (
    FileUpload,
    NoteHistory,
    Notes,
    Test,
    Test_Import,
    Test_Type,
)
from dojo.risk_acceptance import api as ra_api
from dojo.test.api.filters import ApiTestFilter, TestImportAPIFilter
from dojo.test.api.serializer import (
    TestCreateSerializer,
    TestImportSerializer,
    TestSerializer,
    TestToFilesSerializer,
    TestToNotesSerializer,
    TestTypeCreateSerializer,
    TestTypeSerializer,
)
from dojo.test.queries import get_authorized_test_imports, get_authorized_tests
from dojo.utils import (
    async_delete,
    generate_file_response,
    get_setting,
    process_tag_notifications,
)


# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class TestsViewSet(
    PrefetchDojoModelViewSet,
    ra_api.AcceptedRisksMixin,
):
    serializer_class = TestSerializer
    queryset = Test.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiTestFilter
    permission_classes = (IsAuthenticated, permissions.UserHasTestPermission)

    @property
    def risk_application_model_class(self):
        return Test

    def get_queryset(self):
        return (
            get_authorized_tests("view")
            .prefetch_related("notes", "files")
            .distinct()
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if get_setting("ASYNC_OBJECT_DELETE"):
            async_del = async_delete()
            async_del.delete(instance)
        else:
            instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_serializer_class(self):
        if self.request and self.request.method == "POST":
            if self.action == "accept_risks":
                return ra_api.AcceptedRiskSerializer
            return TestCreateSerializer
        return TestSerializer

    @extend_schema(
        request=api_v2_serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: api_v2_serializers.ReportGenerateSerializer},
    )
    @action(
        detail=True, methods=["post"],
        # IsAuthenticated only: report generation requires View permission,
        # enforced by the permission-filtered get_queryset(). The viewset's
        # permission_classes would check Edit (POST), which is too restrictive.
        permission_classes=[IsAuthenticated],
    )
    def generate_report(self, request, pk=None):
        test = self.get_object()

        options = {}
        # prepare post data
        report_options = api_v2_serializers.ReportGenerateOptionSerializer(
            data=request.data,
        )
        if report_options.is_valid():
            options["include_finding_notes"] = report_options.validated_data[
                "include_finding_notes"
            ]
            options["include_finding_images"] = report_options.validated_data[
                "include_finding_images"
            ]
            options[
                "include_executive_summary"
            ] = report_options.validated_data["include_executive_summary"]
            options[
                "include_table_of_contents"
            ] = report_options.validated_data["include_table_of_contents"]
            options["report_type"] = report_options.validated_data["report_type"]
        else:
            return Response(
                report_options.errors, status=status.HTTP_400_BAD_REQUEST,
            )

        return report_generate_response(request, test, options)

    @extend_schema(
        methods=["GET"],
        responses={status.HTTP_200_OK: TestToNotesSerializer},
    )
    @extend_schema(
        methods=["POST"],
        request=api_v2_serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: api_v2_serializers.NoteSerializer},
    )
    @action(detail=True, methods=["get", "post"], permission_classes=(IsAuthenticated, permissions.UserHasTestNotePermission))
    def notes(self, request, pk=None):
        test = self.get_object()
        if request.method == "POST":
            new_note = api_v2_serializers.AddNewNoteOptionSerializer(
                data=request.data,
            )
            if new_note.is_valid():
                entry = new_note.validated_data["entry"]
                private = new_note.validated_data.get("private", False)
                note_type = new_note.validated_data.get("note_type", None)
            else:
                return Response(
                    new_note.errors, status=status.HTTP_400_BAD_REQUEST,
                )

            notes = test.notes.filter(note_type=note_type).first()
            if notes and note_type and note_type.is_single:
                return Response("Only one instance of this note_type allowed on a test.", status=status.HTTP_400_BAD_REQUEST)

            author = request.user
            note = Notes(
                entry=entry,
                author=author,
                private=private,
                note_type=note_type,
            )
            note.save()
            # Add an entry to the note history
            history = NoteHistory.objects.create(data=note.entry, time=note.date, current_editor=note.author)
            note.history.add(history)
            # Now add the note to the object
            test.notes.add(note)
            # Determine if we need to send any notifications for user mentioned
            process_tag_notifications(
                request=request,
                note=note,
                parent_url=request.build_absolute_uri(
                    reverse("view_test", args=(test.id,)),
                ),
                parent_title=f"Test: {test.title}",
            )

            serialized_note = api_v2_serializers.NoteSerializer(
                {"author": author, "entry": entry, "private": private},
            )
            return Response(
                serialized_note.data, status=status.HTTP_201_CREATED,
            )
        notes = test.notes.all()

        serialized_notes = TestToNotesSerializer(
            {"test_id": test, "notes": notes},
        )
        return Response(serialized_notes.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={status.HTTP_200_OK: TestToFilesSerializer},
    )
    @extend_schema(
        methods=["POST"],
        request=api_v2_serializers.AddNewFileOptionSerializer,
        responses={status.HTTP_201_CREATED: api_v2_serializers.FileSerializer},
    )
    @action(
        detail=True, methods=["get", "post"], parser_classes=(MultiPartParser,), permission_classes=(IsAuthenticated, permissions.UserHasTestFilePermission),
    )
    def files(self, request, pk=None):
        test = self.get_object()
        if request.method == "POST":
            new_file = api_v2_serializers.FileSerializer(data=request.data)
            if new_file.is_valid():
                title = new_file.validated_data["title"]
                file = new_file.validated_data["file"]
            else:
                return Response(
                    new_file.errors, status=status.HTTP_400_BAD_REQUEST,
                )

            file = FileUpload(title=title, file=file)
            file.save()
            test.files.add(file)

            serialized_file = api_v2_serializers.FileSerializer(file)
            return Response(
                serialized_file.data, status=status.HTTP_201_CREATED,
            )

        files = test.files.all()
        serialized_files = TestToFilesSerializer(
            {"test_id": test, "files": files},
        )
        return Response(serialized_files.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: api_v2_serializers.RawFileSerializer,
        },
    )
    @action(
        detail=True,
        methods=["get"],
        url_path=r"files/download/(?P<file_id>\d+)",
        permission_classes=(IsAuthenticated, permissions.UserHasTestFilePermission),
    )
    def download_file(self, request, file_id, pk=None):
        test = self.get_object()
        # Get the file object
        file_object_qs = test.files.filter(id=file_id)
        file_object = (
            file_object_qs.first() if len(file_object_qs) > 0 else None
        )
        if file_object is None:
            return Response(
                {"error": "File ID not associated with Test"},
                status=status.HTTP_404_NOT_FOUND,
            )
        # send file
        return generate_file_response(file_object)


# Authorization: authenticated, configuration
class TestTypesViewSet(
    mixins.UpdateModelMixin,
    mixins.CreateModelMixin,
    viewsets.ReadOnlyModelViewSet,
):
    serializer_class = TestTypeSerializer
    queryset = Test_Type.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "name",
    ]
    permission_classes = (IsAuthenticated, DjangoModelPermissions)

    def get_queryset(self):
        return Test_Type.objects.all().order_by("id")

    def get_serializer_class(self):
        if self.action == "create":
            return TestTypeCreateSerializer
        return TestTypeSerializer


# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class TestImportViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = TestImportSerializer
    queryset = Test_Import.objects.none()
    filter_backends = (DjangoFilterBackend,)

    filterset_class = TestImportAPIFilter

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasTestImportPermission,
    )

    def get_queryset(self):
        return get_authorized_test_imports(
            "view",
        ).prefetch_related(
            "test_import_finding_action_set",
            "findings_affected",
            "findings_affected__endpoints",
            "findings_affected__status_finding",
            "findings_affected__finding_meta",
            "findings_affected__jira_issue",
            "findings_affected__burprawrequestresponse_set",
            "findings_affected__jira_issue",
            "findings_affected__jira_issue",
            "findings_affected__jira_issue",
            "findings_affected__reviewers",
            "findings_affected__notes",
            "findings_affected__notes__author",
            "findings_affected__notes__history",
            "findings_affected__files",
            "findings_affected__found_by",
            "findings_affected__tags",
            "findings_affected__risk_acceptance_set",
            "test",
            "test__tags",
            "test__notes",
            "test__notes__author",
            "test__files",
            "test__test_type",
            "test__engagement",
            "test__environment",
            "test__engagement__product",
            "test__engagement__product__prod_type",
        )
