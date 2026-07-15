import base64
import logging

import tagulous
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

import dojo.finding.helper as finding_helper
from dojo.api_v2 import (
    mixins as dojo_mixins,
)
from dojo.api_v2 import (
    prefetch,
)
from dojo.api_v2 import (
    serializers as api_v2_serializers,
)
from dojo.api_v2.views import (
    DojoModelViewSet,
    get_request_boolean,
    report_generate_response,
)
from dojo.authorization import api_permissions as permissions
from dojo.finding.api.filters import ApiFindingFilter, ApiTemplateFindingFilter
from dojo.finding.api.serializer import (
    BurpRawRequestResponseMultiSerializer,
    BurpRawRequestResponseSerializer,
    FindingBulkUpdateSerializer,
    FindingCloseSerializer,
    FindingCreateSerializer,
    FindingMetaSerializer,
    FindingNoteSerializer,
    FindingSerializer,
    FindingTemplateSerializer,
    FindingToFilesSerializer,
    FindingToNotesSerializer,
    FindingVerifySerializer,
)
from dojo.finding.queries import get_authorized_findings
from dojo.finding.ui.views import (
    duplicate_cluster,
    reset_finding_duplicate_status_internal,
    set_finding_as_original_internal,
)
from dojo.jira import services as jira_services
from dojo.models import (
    BurpRawRequestResponse,
    DojoMeta,
    FileUpload,
    Finding,
    Finding_Template,
    NoteHistory,
    Notes,
)
from dojo.risk_acceptance import api as ra_api
from dojo.utils import (
    generate_file_response,
    get_system_setting,
    process_tag_notifications,
)

logger = logging.getLogger(__name__)


# Authorization: configuration
class FindingTemplatesViewSet(
    DojoModelViewSet,
):
    serializer_class = FindingTemplateSerializer
    queryset = Finding_Template.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiTemplateFindingFilter
    permission_classes = (permissions.UserHasConfigurationPermissionStaff,)

    def get_queryset(self):
        return Finding_Template.objects.all().order_by("id")


# Authorization: object-based
@extend_schema_view(
    list=extend_schema(
        parameters=[
            OpenApiParameter(
                "related_fields",
                OpenApiTypes.BOOL,
                OpenApiParameter.QUERY,
                required=False,
                description="Expand finding external relations (engagement, environment, product, \
                                            product_type, test, test_type)",
            ),
            OpenApiParameter(
                "prefetch",
                OpenApiTypes.STR,
                OpenApiParameter.QUERY,
                required=False,
                description="List of fields for which to prefetch model instances and add those to the response",
            ),
        ],
    ),
    retrieve=extend_schema(
        parameters=[
            OpenApiParameter(
                "related_fields",
                OpenApiTypes.BOOL,
                OpenApiParameter.QUERY,
                required=False,
                description="Expand finding external relations (engagement, environment, product, \
                                            product_type, test, test_type)",
            ),
            OpenApiParameter(
                "prefetch",
                OpenApiTypes.STR,
                OpenApiParameter.QUERY,
                required=False,
                description="List of fields for which to prefetch model instances and add those to the response",
            ),
        ],
    ),
    destroy=extend_schema(
        parameters=[
            OpenApiParameter(
                "push_to_jira",
                OpenApiTypes.BOOL,
                OpenApiParameter.QUERY,
                required=False,
                description="Close or reassign the linked JIRA issue when deleting this finding.",
            ),
        ],
    ),
)
class FindingViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    mixins.CreateModelMixin,
    ra_api.AcceptedFindingsMixin,
    viewsets.GenericViewSet,
    dojo_mixins.DeletePreviewModelMixin,
):
    serializer_class = FindingSerializer
    queryset = Finding.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiFindingFilter
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasFindingPermission,
    )

    # Overriding mixins.UpdateModeMixin perform_update() method to grab push_to_jira
    # data and add that as a parameter to .save()
    def perform_update(self, serializer):
        # IF JIRA is enabled and this product has a JIRA configuration
        push_to_jira = serializer.validated_data.get("push_to_jira")
        jira_project = jira_services.get_project(serializer.instance)
        if get_system_setting("enable_jira") and jira_project:
            push_to_jira = push_to_jira or jira_project.push_all_issues

        serializer.save(push_to_jira=push_to_jira)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        try:
            push_to_jira = get_request_boolean(request, "push_to_jira")
        except DRFValidationError as error:
            raise DRFValidationError({"push_to_jira": error.detail}) from error
        instance.delete(push_to_jira=push_to_jira)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_queryset(self):
        if settings.V3_FEATURE_LOCATIONS:
            findings = get_authorized_findings(
                "view",
            ).prefetch_related(
                "locations__location__url",
                "reviewers",
                "found_by",
                "notes",
                "risk_acceptance_set",
                "test",
                "tags",
                "jira_issue",
                "finding_group_set",
                "files",
                "burprawrequestresponse_set",
                "status_finding",
                "finding_meta",
                "test__test_type",
                "test__engagement",
                "test__environment",
                "test__engagement__product",
                "test__engagement__product__prod_type",
            )
        else:
            # TODO: Delete this after the move to Locations
            findings = get_authorized_findings(
                "view",
            ).prefetch_related(
                "endpoints",
                "reviewers",
                "found_by",
                "notes",
                "risk_acceptance_set",
                "test",
                "tags",
                "jira_issue",
                "finding_group_set",
                "files",
                "burprawrequestresponse_set",
                "status_finding",
                "finding_meta",
                "test__test_type",
                "test__engagement",
                "test__environment",
                "test__engagement__product",
                "test__engagement__product__prod_type",
            )

        # No blanket .distinct(): get_authorized_findings filters by a scalar product-id IN (no row
        # multiplication), the prefetches above don't join, and ApiFindingFilter rewrites its to-many
        # value filters (endpoints/found_by/reviewers/finding_group/risk_acceptance) as Exists() while
        # ordering by to-many fields aggregates via MultivaluedOrderingFilter. Tag filters still apply
        # DojoFilter.qs's tag-conditional distinct. A query-wide DISTINCT over the full wide-row finding
        # result set forces an expensive sort/hash-aggregate on every list request, so it's dropped.
        return findings

    def get_serializer_class(self):
        if self.request and self.request.method == "POST":
            return FindingCreateSerializer
        return FindingSerializer

    @extend_schema(
        methods=["POST"],
        request=FindingCloseSerializer,
        responses={status.HTTP_200_OK: FindingCloseSerializer},
    )
    @action(detail=True, methods=["post"], permission_classes=(IsAuthenticated, permissions.UserHasFindingRelatedObjectPermission))
    def close(self, request, pk=None):
        finding = self.get_object()

        if request.method == "POST":
            finding_close = FindingCloseSerializer(
                data=request.data,
                context={"request": request},
            )
            if finding_close.is_valid():
                # Remove the prefetched tags to avoid issues with delegating to celery
                finding.tags._remove_prefetched_objects()
                # Use shared helper to perform close operations
                finding_helper.close_finding(
                    finding=finding,
                    user=request.user,
                    is_mitigated=finding_close.validated_data["is_mitigated"],
                    mitigated=(finding_close.validated_data.get("mitigated") if finding_helper.can_edit_mitigated_data(request.user) else timezone.now()),
                    mitigated_by=finding_close.validated_data.get("mitigated_by") or (request.user if not finding_helper.can_edit_mitigated_data(request.user) else None),
                    false_p=finding_close.validated_data.get("false_p", False),
                    out_of_scope=finding_close.validated_data.get("out_of_scope", False),
                    duplicate=finding_close.validated_data.get("duplicate", False),
                    note_entry=finding_close.validated_data.get("note"),
                    note_type=finding_close.validated_data.get("note_type"),
                )
            else:
                return Response(
                    finding_close.errors, status=status.HTTP_400_BAD_REQUEST,
                )
        serialized_finding = FindingCloseSerializer(finding, context={"request": request})
        return Response(serialized_finding.data)

    @extend_schema(
        methods=["POST"],
        request=FindingVerifySerializer,
        responses={status.HTTP_200_OK: FindingSerializer},
    )
    @action(detail=True, methods=["post"], permission_classes=(IsAuthenticated, permissions.UserHasFindingRelatedObjectPermission))
    def verify(self, request, pk=None):
        finding = self.get_object()

        serializer = FindingVerifySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Remove prefetched tags to keep queryset state in sync
        finding.tags._remove_prefetched_objects()

        finding_helper.verify_finding(
            finding=finding,
            user=request.user,
            note_entry=serializer.validated_data.get("note"),
            note_type=serializer.validated_data.get("note_type"),
        )

        serialized_finding = FindingSerializer(finding, context={"request": request})
        return Response(serialized_finding.data)

    @extend_schema(
        methods=["GET"],
        responses={status.HTTP_200_OK: api_v2_serializers.TagSerializer},
    )
    @extend_schema(
        methods=["POST"],
        request=api_v2_serializers.TagSerializer,
        responses={status.HTTP_201_CREATED: api_v2_serializers.TagSerializer},
    )
    @action(detail=True, methods=["get", "post"], permission_classes=(IsAuthenticated, permissions.UserHasFindingRelatedObjectPermission))
    def tags(self, request, pk=None):
        finding = self.get_object()

        if request.method == "POST":
            new_tags = api_v2_serializers.TagSerializer(data=request.data)
            if new_tags.is_valid():
                all_tags = finding.tags
                all_tags = api_v2_serializers.TagSerializer({"tags": all_tags}).data[
                    "tags"
                ]
                for tag in new_tags.validated_data["tags"]:
                    for sub_tag in tagulous.utils.parse_tags(tag):
                        if sub_tag not in all_tags:
                            all_tags.append(sub_tag)

                new_tags = tagulous.utils.render_tags(all_tags)

                finding.tags = new_tags
                finding.save()
            else:
                return Response(
                    new_tags.errors, status=status.HTTP_400_BAD_REQUEST,
                )
        tags = finding.tags
        serialized_tags = api_v2_serializers.TagSerializer({"tags": tags})
        return Response(serialized_tags.data)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: BurpRawRequestResponseSerializer,
        },
    )
    @extend_schema(
        methods=["POST"],
        request=BurpRawRequestResponseSerializer,
        responses={
            status.HTTP_201_CREATED: BurpRawRequestResponseSerializer,
        },
    )
    @action(detail=True, methods=["get", "post"], permission_classes=(IsAuthenticated, permissions.UserHasFindingRelatedObjectPermission))
    def request_response(self, request, pk=None):
        finding = self.get_object()

        if request.method == "POST":
            burps = BurpRawRequestResponseSerializer(
                data=request.data, many=isinstance(request.data, list),
            )
            if burps.is_valid():
                for pair in burps.validated_data["req_resp"]:
                    burp_rr = BurpRawRequestResponse(
                        finding=finding,
                        burpRequestBase64=base64.b64encode(
                            pair["request"].encode("utf-8"),
                        ),
                        burpResponseBase64=base64.b64encode(
                            pair["response"].encode("utf-8"),
                        ),
                    )
                    burp_rr.clean()
                    burp_rr.save()
            else:
                return Response(
                    burps.errors, status=status.HTTP_400_BAD_REQUEST,
                )
        # Not necessarily Burp scan specific - these are just any request/response pairs
        burp_req_resp = BurpRawRequestResponse.objects.filter(finding=finding)
        var = settings.MAX_REQRESP_FROM_API
        if var > -1:
            burp_req_resp = burp_req_resp[:var]

        burp_list = []
        for burp in burp_req_resp:
            request = burp.get_request()
            response = burp.get_response()
            burp_list.append({"request": request, "response": response})
        serialized_burps = BurpRawRequestResponseSerializer(
            {"req_resp": burp_list},
        )
        return Response(serialized_burps.data)

    @extend_schema(
        methods=["GET"],
        responses={status.HTTP_200_OK: FindingToNotesSerializer},
    )
    @extend_schema(
        methods=["POST"],
        request=api_v2_serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: api_v2_serializers.NoteSerializer},
    )
    @action(detail=True, methods=["get", "post"], permission_classes=(IsAuthenticated, permissions.UserHasFindingNotePermission))
    def notes(self, request, pk=None):
        finding = self.get_object()
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

            if finding.notes:
                notes = finding.notes.filter(note_type=note_type).first()
                if notes and note_type and note_type.is_single:
                    return Response("Only one instance of this note_type allowed on a finding.", status=status.HTTP_400_BAD_REQUEST)

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
            finding.last_reviewed = note.date
            finding.last_reviewed_by = author
            finding.save(update_fields=["last_reviewed", "last_reviewed_by", "updated"])
            finding.notes.add(note)
            # Determine if we need to send any notifications for user mentioned
            process_tag_notifications(
                request=request,
                note=note,
                parent_url=request.build_absolute_uri(
                    reverse("view_finding", args=(finding.id,)),
                ),
                parent_title=f"Finding: {finding.title}",
            )

            if finding.has_jira_issue:
                jira_services.add_comment(finding, note)
            elif finding.has_jira_group_issue:
                jira_services.add_comment(finding.finding_group, note)

            serialized_note = api_v2_serializers.NoteSerializer(
                {"author": author, "entry": entry, "private": private},
            )
            return Response(
                serialized_note.data, status=status.HTTP_201_CREATED,
            )
        notes = finding.notes.all()

        serialized_notes = FindingToNotesSerializer(
            {"finding_id": finding, "notes": notes},
        )
        return Response(serialized_notes.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={status.HTTP_200_OK: FindingToFilesSerializer},
    )
    @extend_schema(
        methods=["POST"],
        request=api_v2_serializers.AddNewFileOptionSerializer,
        responses={status.HTTP_201_CREATED: api_v2_serializers.FileSerializer},
    )
    @action(
        detail=True, methods=["get", "post"], parser_classes=(MultiPartParser,), permission_classes=(IsAuthenticated, permissions.UserHasFindingFilePermission),
    )
    def files(self, request, pk=None):
        finding = self.get_object()
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
            finding.files.add(file)

            serialized_file = api_v2_serializers.FileSerializer(file)
            return Response(
                serialized_file.data, status=status.HTTP_201_CREATED,
            )

        files = finding.files.all()
        serialized_files = FindingToFilesSerializer(
            {"finding_id": finding, "files": files},
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
        url_path=r"files/download/(?P<file_id>\d+)", permission_classes=(IsAuthenticated, permissions.UserHasFindingFilePermission),
    )
    def download_file(self, request, file_id, pk=None):
        finding = self.get_object()
        # Get the file object
        file_object_qs = finding.files.filter(id=file_id)
        file_object = (
            file_object_qs.first() if len(file_object_qs) > 0 else None
        )
        if file_object is None:
            return Response(
                {"error": "File ID not associated with Finding"},
                status=status.HTTP_404_NOT_FOUND,
            )
        # send file
        return generate_file_response(file_object)

    @extend_schema(
        request=FindingNoteSerializer,
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @action(detail=True, methods=["patch"], permission_classes=(IsAuthenticated, permissions.UserHasFindingNotePermission))
    def remove_note(self, request, pk=None):
        """Remove Note From Finding Note"""
        finding = self.get_object()
        notes = finding.notes.all()
        if request.data["note_id"]:
            note = get_object_or_404(Notes.objects, id=request.data["note_id"])
            if note not in notes:
                return Response(
                    {"error": "Selected Note is not assigned to this Finding"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                {"error": "('note_id') parameter missing"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if (
            note.author.username == request.user.username
            or request.user.is_superuser
        ):
            finding.notes.remove(note)
            note.delete()
        else:
            return Response(
                {"error": "Delete Failed, You are not the Note's author"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {"Success": "Selected Note has been Removed successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )

    @extend_schema(
        methods=["PUT", "PATCH"],
        request=api_v2_serializers.TagSerializer,
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @action(detail=True, methods=["put", "patch"], permission_classes=(IsAuthenticated, permissions.UserHasFindingRelatedObjectPermission))
    def remove_tags(self, request, pk=None):
        """Remove Tag(s) from finding list of tags"""
        finding = self.get_object()
        delete_tags = api_v2_serializers.TagSerializer(data=request.data)
        if delete_tags.is_valid():
            all_tags = finding.tags
            all_tags = api_v2_serializers.TagSerializer({"tags": all_tags}).data[
                "tags"
            ]

            # serializer turns it into a string, but we need a list
            del_tags = delete_tags.validated_data["tags"]
            if len(del_tags) < 1:
                return Response(
                    {"error": "Empty Tag List Not Allowed"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            for tag in del_tags:
                if tag not in all_tags:
                    return Response(
                        {
                            "error": f"'{tag}' is not a valid tag in list '{all_tags}'",
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                all_tags.remove(tag)
            new_tags = tagulous.utils.render_tags(all_tags)
            finding.tags = new_tags
            finding.save()
            return Response(
                {"success": "Tag(s) Removed"},
                status=status.HTTP_204_NO_CONTENT,
            )
        return Response(
            delete_tags.errors, status=status.HTTP_400_BAD_REQUEST,
        )

    @extend_schema(
        responses={
            status.HTTP_200_OK: FindingSerializer(many=True),
        },
    )
    @action(
        detail=True,
        methods=["get"],
        url_path=r"duplicate",
        filter_backends=[],
        pagination_class=None,
        permission_classes=(IsAuthenticated, permissions.UserHasFindingRelatedObjectPermission),
    )
    def get_duplicate_cluster(self, request, pk):
        finding = self.get_object()
        result = duplicate_cluster(request, finding)
        serializer = FindingSerializer(
            instance=result, many=True, context={"request": request},
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        request=OpenApiTypes.NONE,
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @action(detail=True, methods=["post"], url_path=r"duplicate/reset", permission_classes=(IsAuthenticated, permissions.UserHasFindingRelatedObjectPermission))
    def reset_finding_duplicate_status(self, request, pk):
        self.get_object()
        checked_duplicate_id = reset_finding_duplicate_status_internal(
            request.user, pk,
        )
        if checked_duplicate_id is None:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        request=OpenApiTypes.NONE,
        parameters=[
            OpenApiParameter(
                "new_fid", OpenApiTypes.INT, OpenApiParameter.PATH,
            ),
        ],
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @action(
        detail=True, methods=["post"], url_path=r"original/(?P<new_fid>\d+)", permission_classes=(IsAuthenticated, permissions.UserHasFindingRelatedObjectPermission),
    )
    def set_finding_as_original(self, request, pk, new_fid):
        self.get_object()
        success = set_finding_as_original_internal(request.user, pk, new_fid)
        if not success:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        methods=["PATCH"],
        request=FindingBulkUpdateSerializer,
        responses={
            status.HTTP_200_OK: FindingSerializer(many=True),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Validation failed: unknown field, invalid value, unknown finding id, "
                            "duplicate id, or more findings than the per-request limit.",
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                description="The user lacks edit permission on at least one referenced finding; "
                            "the entire batch is rejected and rolled back.",
            ),
        },
    )
    @action(
        detail=False,
        methods=["patch"],
        url_path="bulk",
        filter_backends=[],
        pagination_class=None,
    )
    def bulk_update(self, request):
        """
        Update an allowlisted set of fields on many findings in a single atomic request.

        The request body is ``{"findings": [{"id": <int>, ...}, ...]}`` where each item
        carries the target finding id plus any subset of the allowlisted fields
        (epss_score, epss_percentile, known_exploited, ransomware_used, kev_date). The
        user must have edit permission on every referenced finding; if any check fails,
        the entire batch is rolled back and a 403 is returned. Findings are never pushed
        to JIRA from this endpoint.
        """
        serializer = FindingBulkUpdateSerializer(
            data=request.data, context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        updated_findings = self._perform_bulk_update(
            request, serializer.validated_data["findings"],
        )
        # Re-fetch through the viewset queryset so the response reuses the same
        # prefetching and authorization scoping as a normal finding list.
        response_findings = self.get_queryset().filter(
            id__in=[finding.id for finding in updated_findings],
        )
        response_serializer = FindingSerializer(
            response_findings, many=True, context={"request": request},
        )
        return Response(response_serializer.data, status=status.HTTP_200_OK)

    @transaction.atomic
    def _perform_bulk_update(self, request, items):
        updated_findings = []
        for item in items:
            finding = item["id"]
            # Per-item authorization mirrors a normal PATCH: require edit permission
            # on each finding. check_object_permissions raises a 403 on the first
            # failure and, because this whole method runs in one transaction, that
            # 403 rolls back any updates already applied earlier in the batch.
            self.check_object_permissions(request, finding)
            for field, value in item.items():
                if field == "id":
                    continue
                setattr(finding, field, value)
            # The allowlisted fields never affect the dedupe hash or JIRA sync, so
            # the expensive post-save processing is skipped for performance. The row
            # is still UPDATEd, which fires the pghistory trigger, so audit history
            # is recorded exactly as it is for a normal PATCH.
            finding.save(
                dedupe_option=False,
                rules_option=False,
                product_grading_option=False,
                issue_updater_option=False,
                push_to_jira=False,
            )
            updated_findings.append(finding)
        return updated_findings

    @extend_schema(
        request=api_v2_serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: api_v2_serializers.ReportGenerateSerializer},
    )
    @action(
        detail=False, methods=["post"],
        # IsAuthenticated only: report generation requires View permission,
        # enforced by the permission-filtered get_queryset(). The viewset's
        # permission_classes would check Edit (POST), which is too restrictive.
        permission_classes=[IsAuthenticated],
    )
    def generate_report(self, request):
        findings = self.get_queryset()
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

        return report_generate_response(request, findings, options)

    def _get_metadata(self, request, finding):
        metadata = DojoMeta.objects.filter(finding=finding)
        serializer = FindingMetaSerializer(
            instance=metadata, many=True,
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    def _edit_metadata(self, request, finding):
        metadata_name = request.query_params.get("name", None)
        if metadata_name is None:
            return Response(
                "Metadata name is required", status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            DojoMeta.objects.update_or_create(
                name=metadata_name,
                finding=finding,
                defaults={
                    "name": request.data.get("name"),
                    "value": request.data.get("value"),
                },
            )

            return Response(data=request.data, status=status.HTTP_200_OK)
        except IntegrityError:
            return Response(
                "Update failed because the new name already exists",
                status=status.HTTP_400_BAD_REQUEST,
            )

    def _add_metadata(self, request, finding):
        metadata_data = FindingMetaSerializer(data=request.data)

        if metadata_data.is_valid():
            name = metadata_data.validated_data["name"]
            value = metadata_data.validated_data["value"]

            metadata = DojoMeta(finding=finding, name=name, value=value)
            try:
                metadata.validate_unique()
                metadata.save()
            except ValidationError:
                return Response(
                    "Create failed probably because the name of the metadata already exists",
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response(data=metadata_data.data, status=status.HTTP_200_OK)
        return Response(
            metadata_data.errors, status=status.HTTP_400_BAD_REQUEST,
        )

    def _remove_metadata(self, request, finding):
        name = request.query_params.get("name", None)
        if name is None:
            return Response(
                "A metadata name must be provided",
                status=status.HTTP_400_BAD_REQUEST,
            )

        metadata = get_object_or_404(
            DojoMeta.objects, finding=finding, name=name,
        )
        metadata.delete()

        return Response("Metadata deleted", status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: FindingMetaSerializer(many=True),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Returned if finding does not exist",
            ),
        },
    )
    @extend_schema(
        methods=["DELETE"],
        parameters=[
            OpenApiParameter(
                "name",
                OpenApiTypes.INT,
                OpenApiParameter.QUERY,
                required=True,
                description="name of the metadata to retrieve. If name is empty, return all the \
                                    metadata associated with the finding",
            ),
        ],
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Returned if the metadata was correctly deleted",
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Returned if finding does not exist",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Returned if there was a problem with the metadata information",
            ),
        },
    )
    @extend_schema(
        methods=["PUT"],
        request=FindingMetaSerializer,
        responses={
            status.HTTP_200_OK: FindingMetaSerializer,
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Returned if finding does not exist",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Returned if there was a problem with the metadata information",
            ),
        },
    )
    @extend_schema(
        methods=["POST"],
        request=FindingMetaSerializer,
        responses={
            status.HTTP_200_OK: FindingMetaSerializer,
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="Returned if finding does not exist",
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Returned if there was a problem with the metadata information",
            ),
        },
    )
    @action(
        detail=True,
        methods=["post", "put", "delete", "get"],
        filter_backends=[],
        pagination_class=None,
        permission_classes=(IsAuthenticated, permissions.UserHasFindingRelatedObjectPermission),
    )
    def metadata(self, request, pk=None):
        finding = self.get_object()

        if request.method == "GET":
            return self._get_metadata(request, finding)
        if request.method == "POST":
            return self._add_metadata(request, finding)
        if request.method in {"PUT", "PATCH"}:
            return self._edit_metadata(request, finding)
        if request.method == "DELETE":
            return self._remove_metadata(request, finding)

        return Response(
            {"error", "unsupported method"}, status=status.HTTP_400_BAD_REQUEST,
        )


class BurpRawRequestResponseViewSet(
    DojoModelViewSet,
):
    serializer_class = BurpRawRequestResponseMultiSerializer
    queryset = BurpRawRequestResponse.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["finding"]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasBurpRawRequestResponsePermission,
    )

    def get_queryset(self):
        return (
            BurpRawRequestResponse.objects.filter(
                finding__in=get_authorized_findings(
                    "view",
                ),
            )
            .exclude(
                burpRequestBase64__exact=b"",
                burpResponseBase64__exact=b"",
            )
            .order_by("id")
        )
