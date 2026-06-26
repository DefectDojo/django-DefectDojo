from django.core.exceptions import ValidationError
from django.urls import reverse
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from dojo.api_v2 import serializers as api_v2_serializers
from dojo.api_v2.prefetch.prefetcher import _Prefetcher
from dojo.api_v2.views import DojoModelViewSet, PrefetchDojoModelViewSet, report_generate, schema_with_prefetch
from dojo.authorization import api_permissions as permissions
from dojo.celery_dispatch import dojo_dispatch_task
from dojo.engagement.api.filters import ApiEngagementFilter
from dojo.engagement.api.serializer import (
    EngagementCheckListSerializer,
    EngagementPresetsSerializer,
    EngagementSerializer,
    EngagementToFilesSerializer,
    EngagementToNotesSerializer,
)
from dojo.engagement.queries import get_authorized_engagements
from dojo.engagement.services import close_engagement, reopen_engagement
from dojo.jira import services as jira_services
from dojo.models import (
    Check_List,
    Engagement,
    Engagement_Presets,
    FileUpload,
    NoteHistory,
    Notes,
)
from dojo.product.queries import get_authorized_engagement_presets
from dojo.risk_acceptance import api as ra_api
from dojo.utils import (
    async_delete,
    generate_file_response,
    get_setting,
    process_tag_notifications,
)


# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class EngagementViewSet(
    # PrefetchDojoModelViewSet,
    DojoModelViewSet,
    ra_api.AcceptedRisksMixin,
):
    serializer_class = EngagementSerializer
    queryset = Engagement.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiEngagementFilter

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasEngagementPermission,
    )

    @property
    def risk_application_model_class(self):
        return Engagement

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if get_setting("ASYNC_OBJECT_DELETE"):
            async_del = async_delete()
            async_del.delete(instance)
        else:
            instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_queryset(self):
        return (
            get_authorized_engagements("view")
            .prefetch_related("notes", "risk_acceptance", "files")
            .distinct()
        )

    @extend_schema(
        request=OpenApiTypes.NONE, responses={status.HTTP_200_OK: ""},
    )
    @action(detail=True, methods=["post"], permission_classes=(IsAuthenticated, permissions.UserHasEngagementRelatedObjectPermission))
    def close(self, request, pk=None):
        eng = self.get_object()
        close_engagement(eng)
        return Response({}, status=status.HTTP_200_OK)

    @extend_schema(
        request=OpenApiTypes.NONE, responses={status.HTTP_200_OK: ""},
    )
    @action(detail=True, methods=["post"], permission_classes=(IsAuthenticated, permissions.UserHasEngagementRelatedObjectPermission))
    def reopen(self, request, pk=None):
        eng = self.get_object()
        reopen_engagement(eng)
        return Response({}, status=status.HTTP_200_OK)

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
        engagement = self.get_object()

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
        else:
            return Response(
                report_options.errors, status=status.HTTP_400_BAD_REQUEST,
            )

        data = report_generate(request, engagement, options)
        report = api_v2_serializers.ReportGenerateSerializer(data)
        return Response(report.data)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: EngagementToNotesSerializer,
        },
    )
    @extend_schema(
        methods=["POST"],
        request=api_v2_serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: api_v2_serializers.NoteSerializer},
    )
    @action(detail=True, methods=["get", "post"], permission_classes=[IsAuthenticated, permissions.UserHasEngagementNotePermission])
    def notes(self, request, pk=None):
        engagement = self.get_object()
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

            notes = engagement.notes.filter(note_type=note_type).first()
            if notes and note_type and note_type.is_single:
                return Response("Only one instance of this note_type allowed on an engagement.", status=status.HTTP_400_BAD_REQUEST)

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
            engagement.notes.add(note)
            # Determine if we need to send any notifications for user mentioned
            process_tag_notifications(
                request=request,
                note=note,
                parent_url=request.build_absolute_uri(
                    reverse("view_engagement", args=(engagement.id,)),
                ),
                parent_title=f"Engagement: {engagement.name}",
            )

            serialized_note = api_v2_serializers.NoteSerializer(
                {"author": author, "entry": entry, "private": private},
            )
            return Response(
                serialized_note.data, status=status.HTTP_201_CREATED,
            )
        notes = engagement.notes.all()

        serialized_notes = EngagementToNotesSerializer(
            {"engagement_id": engagement, "notes": notes},
        )
        return Response(serialized_notes.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: EngagementToFilesSerializer,
        },
    )
    @extend_schema(
        methods=["POST"],
        request=api_v2_serializers.AddNewFileOptionSerializer,
        responses={status.HTTP_201_CREATED: api_v2_serializers.FileSerializer},
    )
    @action(
        detail=True, methods=["get", "post"], parser_classes=(MultiPartParser,), permission_classes=[IsAuthenticated, permissions.UserHasEngagementRelatedObjectPermission],
    )
    def files(self, request, pk=None):
        engagement = self.get_object()
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
            engagement.files.add(file)

            serialized_file = api_v2_serializers.FileSerializer(file)
            return Response(
                serialized_file.data, status=status.HTTP_201_CREATED,
            )

        files = engagement.files.all()
        serialized_files = EngagementToFilesSerializer(
            {"engagement_id": engagement, "files": files},
        )
        return Response(serialized_files.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["POST"],
        request=EngagementCheckListSerializer,
        responses={
            status.HTTP_201_CREATED: EngagementCheckListSerializer,
        },
    )
    @action(detail=True, methods=["get", "post"], permission_classes=[IsAuthenticated, permissions.UserHasEngagementRelatedObjectPermission])
    def complete_checklist(self, request, pk=None):
        engagement = self.get_object()
        check_lists = Check_List.objects.filter(engagement=engagement)
        if request.method == "POST":
            if check_lists.count() > 0:
                return Response(
                    {
                        "message": "A completed checklist for this engagement already exists.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            check_list = EngagementCheckListSerializer(
                data=request.data,
            )
            if not check_list.is_valid():
                return Response(
                    check_list.errors, status=status.HTTP_400_BAD_REQUEST,
                )
            check_list = Check_List(**check_list.data)
            check_list.engagement = engagement
            check_list.save()
            serialized_check_list = EngagementCheckListSerializer(
                check_list,
            )
            return Response(
                serialized_check_list.data, status=status.HTTP_201_CREATED,
            )
        prefetch_params = request.GET.get("prefetch", "").split(",")
        prefetcher = _Prefetcher()
        entry = check_lists.first()
        # Get the queried object representation
        result = EngagementCheckListSerializer(entry).data
        prefetcher._prefetch(entry, prefetch_params)
        result["prefetch"] = prefetcher.prefetched_data
        return Response(result, status=status.HTTP_200_OK)

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
        permission_classes=[IsAuthenticated, permissions.UserHasEngagementRelatedObjectPermission],
    )
    def download_file(self, request, file_id, pk=None):
        engagement = self.get_object()
        # Get the file object
        file_object_qs = engagement.files.filter(id=file_id)
        file_object = (
            file_object_qs.first() if len(file_object_qs) > 0 else None
        )
        if file_object is None:
            return Response(
                {"error": "File ID not associated with Engagement"},
                status=status.HTTP_404_NOT_FOUND,
            )
        # send file
        return generate_file_response(file_object)

    @extend_schema(
        request=api_v2_serializers.EngagementUpdateJiraEpicSerializer,
        responses={status.HTTP_200_OK: api_v2_serializers.EngagementUpdateJiraEpicSerializer},
    )
    @action(
        detail=True, methods=["post"],
        permission_classes=(IsAuthenticated, permissions.UserHasEngagementRelatedObjectPermission),
    )
    def update_jira_epic(self, request, pk=None):
        engagement = self.get_object()
        try:
            if engagement.has_jira_issue:
                task = jira_services.get_epic_task("update_epic")
                if task:
                    dojo_dispatch_task(task, engagement.id, **request.data)
                response = Response(
                    {"info": "Jira Epic update query sent"},
                    status=status.HTTP_200_OK,
                )
            else:
                task = jira_services.get_epic_task("add_epic")
                if task:
                    dojo_dispatch_task(task, engagement.id, **request.data)
                response = Response(
                    {"info": "Jira Epic create query sent"},
                    status=status.HTTP_200_OK,
                )
        except ValidationError:
            return Response(
                {"error": "Bad Request!"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return response


@extend_schema_view(**schema_with_prefetch())
class EngagementPresetsViewset(
    PrefetchDojoModelViewSet,
):
    serializer_class = EngagementPresetsSerializer
    queryset = Engagement_Presets.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "title", "product"]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasEngagementPresetPermission,
    )

    def get_queryset(self):
        return get_authorized_engagement_presets("view")
