from rest_framework.generics import GenericAPIView
from drf_spectacular.types import OpenApiTypes
from crum import get_current_user
from django.http import HttpResponse, Http404, FileResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.utils.decorators import method_decorator
from drf_yasg.inspectors.base import NotHandled
from drf_yasg.inspectors.query import CoreAPICompatInspector
from rest_framework import viewsets, mixins, status
from rest_framework.response import Response
from django.db import IntegrityError
from rest_framework.permissions import DjangoModelPermissions, IsAuthenticated
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema, no_body
import base64
import mimetypes
from dojo.engagement.services import close_engagement, reopen_engagement
from dojo.importers.reimporter.utils import get_target_engagement_if_exists, get_target_product_if_exists, get_target_test_if_exists
from dojo.models import Language_Type, Languages, Notifications, Product, Product_Type, Engagement, SLA_Configuration, \
    Test, Test_Import, Test_Type, Finding, \
    User, Stub_Finding, Finding_Template, Notes, \
    JIRA_Issue, Tool_Product_Settings, Tool_Configuration, Tool_Type, \
    Endpoint, JIRA_Project, JIRA_Instance, DojoMeta, Development_Environment, \
    Dojo_User, Note_Type, System_Settings, App_Analysis, Endpoint_Status, \
    Sonarqube_Issue, Sonarqube_Issue_Transition, Regulation, Risk_Acceptance, \
    BurpRawRequestResponse, FileUpload, Product_Type_Member, Product_Member, Dojo_Group, \
    Product_Group, Product_Type_Group, Role, Global_Role, Dojo_Group_Member, Engagement_Presets, Network_Locations, \
    UserContactInfo, Product_API_Scan_Configuration, Cred_Mapping, Cred_User, Question, Answer, \
    Engagement_Survey, Answered_Survey, General_Survey, Check_List
from dojo.endpoint.views import get_endpoint_ids
from dojo.reports.views import report_url_resolver, prefetch_related_findings_for_report
from dojo.finding.views import set_finding_as_original_internal, reset_finding_duplicate_status_internal, \
    duplicate_cluster
from dojo.filters import ReportFindingFilter, ApiCredentialsFilter, \
    ApiFindingFilter, ApiProductFilter, ApiEngagementFilter, ApiEndpointFilter, \
    ApiAppAnalysisFilter, ApiTestFilter, ApiTemplateFindingFilter, ApiRiskAcceptanceFilter
from dojo.risk_acceptance import api as ra_api
from dateutil.relativedelta import relativedelta
from django.conf import settings
from datetime import datetime
from dojo.utils import get_period_counts_legacy, get_system_setting, get_setting, async_delete
from dojo.api_v2 import serializers, permissions, prefetch, schema, mixins as dojo_mixins
import dojo.jira_link.helper as jira_helper
import logging
import tagulous
from dojo.product_type.queries import get_authorized_product_types, get_authorized_product_type_members, \
    get_authorized_product_type_groups
from dojo.product.queries import get_authorized_products, get_authorized_app_analysis, get_authorized_dojo_meta, \
    get_authorized_product_members, get_authorized_product_groups, get_authorized_languages, \
    get_authorized_engagement_presets, get_authorized_product_api_scan_configurations
from dojo.engagement.queries import get_authorized_engagements
from dojo.risk_acceptance.queries import get_authorized_risk_acceptances
from dojo.test.queries import get_authorized_tests, get_authorized_test_imports
from dojo.finding.queries import get_authorized_findings, get_authorized_stub_findings
from dojo.endpoint.queries import get_authorized_endpoints, get_authorized_endpoint_status
from dojo.group.queries import get_authorized_groups, get_authorized_group_members
from dojo.jira_link.queries import get_authorized_jira_projects, get_authorized_jira_issues
from dojo.tool_product.queries import get_authorized_tool_product_settings
from dojo.cred.queries import get_authorized_cred_mappings
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from dojo.authorization.roles_permissions import Permissions
from dojo.user.utils import get_configuration_permissions_codenames

logger = logging.getLogger(__name__)


# Authorization: authenticated users
class RoleViewSet(mixins.ListModelMixin,
                  mixins.RetrieveModelMixin,
                  viewsets.GenericViewSet):
    serializer_class = serializers.RoleSerializer
    queryset = Role.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'name')
    permission_classes = (IsAuthenticated, )


# Authorization: object-based
@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class DojoGroupViewSet(prefetch.PrefetchListMixin,
                       prefetch.PrefetchRetrieveMixin,
                       mixins.ListModelMixin,
                       mixins.RetrieveModelMixin,
                       mixins.DestroyModelMixin,
                       mixins.UpdateModelMixin,
                       mixins.CreateModelMixin,
                       viewsets.GenericViewSet,
                       dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.DojoGroupSerializer
    queryset = Dojo_Group.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'name', 'social_provider')
    swagger_schema = prefetch.get_prefetch_schema(["dojo_groups_list", "dojo_groups_read"],
        serializers.DojoGroupSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasDojoGroupPermission)

    def get_queryset(self):
        return get_authorized_groups(Permissions.Group_View).distinct()


# Authorization: object-based
@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class DojoGroupMemberViewSet(prefetch.PrefetchListMixin,
                           prefetch.PrefetchRetrieveMixin,
                           mixins.ListModelMixin,
                           mixins.RetrieveModelMixin,
                           mixins.CreateModelMixin,
                           mixins.DestroyModelMixin,
                           mixins.UpdateModelMixin,
                           viewsets.GenericViewSet,
                           dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.DojoGroupMemberSerializer
    queryset = Dojo_Group_Member.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'group_id', 'user_id')
    swagger_schema = prefetch.get_prefetch_schema(["dojo_group_members_list", "dojo_group_members_read"],
        serializers.DojoGroupMemberSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasDojoGroupMemberPermission)

    def get_queryset(self):
        return get_authorized_group_members(Permissions.Group_View).distinct()

    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {'message': 'Patch function is not offered in this path.'}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Authorization: superuser
class GlobalRoleViewSet(prefetch.PrefetchListMixin,
                        prefetch.PrefetchRetrieveMixin,
                        mixins.ListModelMixin,
                        mixins.RetrieveModelMixin,
                        mixins.DestroyModelMixin,
                        mixins.UpdateModelMixin,
                        mixins.CreateModelMixin,
                        viewsets.GenericViewSet,
                        dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.GlobalRoleSerializer
    queryset = Global_Role.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'user', 'group', 'role')
    swagger_schema = prefetch.get_prefetch_schema(["global_roles_list", "global_roles_read"],
        serializers.GlobalRoleSerializer).to_schema()
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)


# Authorization: object-based
class EndPointViewSet(prefetch.PrefetchListMixin,
                      prefetch.PrefetchRetrieveMixin,
                      mixins.ListModelMixin,
                      mixins.RetrieveModelMixin,
                      mixins.UpdateModelMixin,
                      mixins.DestroyModelMixin,
                      mixins.CreateModelMixin,
                      viewsets.GenericViewSet,
                      dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.EndpointSerializer
    queryset = Endpoint.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiEndpointFilter
    swagger_schema = prefetch.get_prefetch_schema(["endpoints_list", "endpoints_read"], serializers.EndpointSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasEndpointPermission)

    def get_queryset(self):
        return get_authorized_endpoints(Permissions.Endpoint_View).distinct()

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @swagger_auto_schema(
        request_body=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def generate_report(self, request, pk=None):
        endpoint = self.get_object()

        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(data=request.data)
        if report_options.is_valid():
            options['include_finding_notes'] = report_options.validated_data['include_finding_notes']
            options['include_finding_images'] = report_options.validated_data['include_finding_images']
            options['include_executive_summary'] = report_options.validated_data['include_executive_summary']
            options['include_table_of_contents'] = report_options.validated_data['include_table_of_contents']
        else:
            return Response(report_options.errors,
                status=status.HTTP_400_BAD_REQUEST)

        data = report_generate(request, endpoint, options)
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)


# Authorization: object-based
class EndpointStatusViewSet(prefetch.PrefetchListMixin,
                            prefetch.PrefetchRetrieveMixin,
                            mixins.ListModelMixin,
                            mixins.RetrieveModelMixin,
                            mixins.UpdateModelMixin,
                            mixins.DestroyModelMixin,
                            mixins.CreateModelMixin,
                            viewsets.GenericViewSet,
                            dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.EndpointStatusSerializer
    queryset = Endpoint_Status.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('mitigated', 'false_positive', 'out_of_scope', 'risk_accepted', 'mitigated_by', 'finding', 'endpoint')
    swagger_schema = prefetch.get_prefetch_schema(["endpoint_status_list", "endpoint_status_read"], serializers.EndpointStatusSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasEndpointStatusPermission)

    def get_queryset(self):
        return get_authorized_endpoint_status(Permissions.Endpoint_View).distinct()


# Authorization: object-based
class EngagementViewSet(prefetch.PrefetchListMixin,
                        prefetch.PrefetchRetrieveMixin,
                        mixins.ListModelMixin,
                        mixins.RetrieveModelMixin,
                        mixins.UpdateModelMixin,
                        mixins.DestroyModelMixin,
                        mixins.CreateModelMixin,
                        ra_api.AcceptedRisksMixin,
                        viewsets.GenericViewSet,
                        dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.EngagementSerializer
    queryset = Engagement.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiEngagementFilter
    swagger_schema = prefetch.get_prefetch_schema(["engagements_list", "engagements_read"], serializers.EngagementSerializer).composeWith(
        prefetch.get_prefetch_schema(["engagements_complete_checklist_read"], serializers.EngagementCheckListSerializer)
    ).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasEngagementPermission)

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
        return get_authorized_engagements(Permissions.Engagement_View).prefetch_related(
                                                    'notes',
                                                    'risk_acceptance',
                                                    'files').distinct()

    @extend_schema(
        request=OpenApiTypes.NONE,
        responses={status.HTTP_200_OK: ""}
    )
    @swagger_auto_schema(
        request_body=no_body, responses={status.HTTP_200_OK: ""}
    )
    @action(detail=True, methods=["post"])
    def close(self, request, pk=None):
        eng = self.get_object()
        close_engagement(eng)
        return HttpResponse()

    @extend_schema(
        request=OpenApiTypes.NONE,
        responses={status.HTTP_200_OK: ""}
    )
    @swagger_auto_schema(
        request_body=no_body, responses={status.HTTP_200_OK: ""}
    )
    @action(detail=True, methods=["post"])
    def reopen(self, request, pk=None):
        eng = self.get_object()
        reopen_engagement(eng)
        return HttpResponse()

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @swagger_auto_schema(
        request_body=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def generate_report(self, request, pk=None):
        engagement = self.get_object()

        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(data=request.data)
        if report_options.is_valid():
            options['include_finding_notes'] = report_options.validated_data['include_finding_notes']
            options['include_finding_images'] = report_options.validated_data['include_finding_images']
            options['include_executive_summary'] = report_options.validated_data['include_executive_summary']
            options['include_table_of_contents'] = report_options.validated_data['include_table_of_contents']
        else:
            return Response(report_options.errors,
                status=status.HTTP_400_BAD_REQUEST)

        data = report_generate(request, engagement, options)
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)

    @extend_schema(
        methods=['GET'],
        responses={status.HTTP_200_OK: serializers.EngagementToNotesSerializer}
    )
    @extend_schema(
        methods=['POST'],
        request=serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.NoteSerializer}
    )
    @swagger_auto_schema(
        method='get',
        responses={status.HTTP_200_OK: serializers.EngagementToNotesSerializer}
    )
    @swagger_auto_schema(
        methods=['post'],
        request_body=serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.NoteSerializer}
    )
    @action(detail=True, methods=["get", "post"])
    def notes(self, request, pk=None):
        engagement = self.get_object()
        if request.method == 'POST':
            new_note = serializers.AddNewNoteOptionSerializer(data=request.data)
            if new_note.is_valid():
                entry = new_note.validated_data['entry']
                private = new_note.validated_data.get('private', False)
                note_type = new_note.validated_data.get('note_type', None)
            else:
                return Response(new_note.errors,
                    status=status.HTTP_400_BAD_REQUEST)

            author = request.user
            note = Notes(entry=entry, author=author, private=private, note_type=note_type)
            note.save()
            engagement.notes.add(note)

            serialized_note = serializers.NoteSerializer({
                "author": author, "entry": entry,
                "private": private
            })
            result = serializers.EngagementToNotesSerializer({
                "engagement_id": engagement, "notes": [serialized_note.data]
            })
            return Response(serialized_note.data,
                status=status.HTTP_201_CREATED)
        notes = engagement.notes.all()

        serialized_notes = serializers.EngagementToNotesSerializer({
                "engagement_id": engagement, "notes": notes
        })
        return Response(serialized_notes.data,
                status=status.HTTP_200_OK)

    @extend_schema(
        methods=['GET'],
        responses={status.HTTP_200_OK: serializers.EngagementToFilesSerializer}
    )
    @extend_schema(
        methods=['POST'],
        request=serializers.AddNewFileOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.FileSerializer}
    )
    @swagger_auto_schema(
        method='get',
        responses={status.HTTP_200_OK: serializers.EngagementToFilesSerializer}
    )
    @swagger_auto_schema(
        method='post',
        request_body=serializers.AddNewFileOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.FileSerializer}
    )
    @action(detail=True, methods=["get", "post"], parser_classes=(MultiPartParser,))
    def files(self, request, pk=None):
        engagement = self.get_object()
        if request.method == 'POST':
            new_file = serializers.FileSerializer(data=request.data)
            if new_file.is_valid():
                title = new_file.validated_data['title']
                file = new_file.validated_data['file']
            else:
                return Response(new_file.errors, status=status.HTTP_400_BAD_REQUEST)

            file = FileUpload(title=title, file=file)
            file.save()
            engagement.files.add(file)

            serialized_file = serializers.FileSerializer(file)
            return Response(serialized_file.data, status=status.HTTP_201_CREATED)

        files = engagement.files.all()
        serialized_files = serializers.EngagementToFilesSerializer({
            "engagement_id": engagement, "files": files
        })
        return Response(serialized_files.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=['POST'],
        request=serializers.EngagementCheckListSerializer,
        responses={status.HTTP_201_CREATED: serializers.EngagementCheckListSerializer}
    )
    @swagger_auto_schema(
        method='post',
        request_body=serializers.EngagementCheckListSerializer,
        responses={status.HTTP_201_CREATED: serializers.EngagementCheckListSerializer}
    )
    @action(detail=True, methods=["get", "post"])
    def complete_checklist(self, request, pk=None):
        from dojo.api_v2.prefetch.prefetcher import _Prefetcher
        engagement = self.get_object()
        check_lists = Check_List.objects.filter(engagement=engagement)
        if request.method == 'POST':
            if check_lists.count() > 0:
                return Response({"message": "A completed checklist for this engagement already exists."}, status=status.HTTP_400_BAD_REQUEST)
            check_list = serializers.EngagementCheckListSerializer(data=request.data)
            if not check_list.is_valid():
                return Response(check_list.errors, status=status.HTTP_400_BAD_REQUEST)
            check_list = Check_List(**check_list.data)
            check_list.engagement = engagement
            check_list.save()
            serialized_check_list = serializers.EngagementCheckListSerializer(check_list)
            return Response(serialized_check_list.data, status=status.HTTP_201_CREATED)
        prefetch_params = request.GET.get("prefetch", "").split(",")
        prefetcher = _Prefetcher()
        entry = check_lists.first()
        # Get the queried object representation
        result = serializers.EngagementCheckListSerializer(entry).data
        prefetcher._prefetch(entry, prefetch_params)
        result["prefetch"] = prefetcher.prefetched_data
        return Response(result, status=status.HTTP_200_OK)

    @extend_schema(
        methods=['GET'],
        responses={
            status.HTTP_200_OK: serializers.RawFileSerializer,
        }
    )
    @swagger_auto_schema(
        method='get',
        responses={
            status.HTTP_200_OK: serializers.RawFileSerializer,
        }
    )
    @action(detail=True, methods=["get"], url_path=r'files/download/(?P<file_id>\d+)')
    def download_file(self, request, file_id, pk=None):
        engagement = self.get_object()
        # Get the file object
        file_object_qs = engagement.files.filter(id=file_id)
        file_object = file_object_qs.first() if len(file_object_qs) > 0 else None
        if file_object is None:
            return Response({"error": "File ID not associated with Engagement"}, status=status.HTTP_404_NOT_FOUND)
        # Get the path of the file in media root
        file_path = f'{settings.MEDIA_ROOT}/{file_object.file.url.lstrip(settings.MEDIA_URL)}'
        file_handle = open(file_path, "rb")
        # send file
        response = FileResponse(file_handle, content_type=f'{mimetypes.guess_type(file_path)}', status=status.HTTP_200_OK)
        response['Content-Length'] = file_object.file.size
        response['Content-Disposition'] = f'attachment; filename="{file_object.file.name}"'

        return response


class RiskAcceptanceViewSet(prefetch.PrefetchListMixin,
                            prefetch.PrefetchRetrieveMixin,
                            mixins.ListModelMixin,
                            mixins.RetrieveModelMixin,
                            mixins.DestroyModelMixin,
                            viewsets.GenericViewSet,
                            dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.RiskAcceptanceSerializer
    queryset = Risk_Acceptance.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiRiskAcceptanceFilter
    swagger_schema = prefetch.get_prefetch_schema(["risk_acceptance_list", "risk_acceptance_read"], serializers.RiskAcceptanceSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasRiskAcceptancePermission)

    def get_queryset(self):
        return get_authorized_risk_acceptances(
            Permissions.Risk_Acceptance).prefetch_related(
                'notes',
                'engagement_set',
                'owner',
                'accepted_findings').distinct()

    @extend_schema(
        methods=['GET'],
        responses={
            status.HTTP_200_OK: serializers.RiskAcceptanceProofSerializer,
        }
    )
    @swagger_auto_schema(
        method='get',
        responses={
            status.HTTP_200_OK: serializers.RiskAcceptanceProofSerializer,
        }
    )
    @action(detail=True, methods=["get"])
    def download_proof(self, request, pk=None):
        risk_acceptance = self.get_object()
        # Get the file object
        file_object = risk_acceptance.path
        if file_object is None or risk_acceptance.filename() is None:
            return Response({"error": "Proof has not provided to this risk acceptance..."}, status=status.HTTP_404_NOT_FOUND)
        # Get the path of the file in media root
        file_path = f'{settings.MEDIA_ROOT}/{file_object.name}'
        file_handle = open(file_path, "rb")
        # send file
        response = FileResponse(file_handle, content_type=f'{mimetypes.guess_type(file_path)}', status=status.HTTP_200_OK)
        response['Content-Length'] = file_object.size
        response['Content-Disposition'] = f'attachment; filename="{risk_acceptance.filename()}"'

        return response


# These are technologies in the UI and the API!
# Authorization: object-based
class AppAnalysisViewSet(prefetch.PrefetchListMixin,
                         prefetch.PrefetchRetrieveMixin,
                         mixins.ListModelMixin,
                         mixins.RetrieveModelMixin,
                         mixins.UpdateModelMixin,
                         mixins.DestroyModelMixin,
                         mixins.CreateModelMixin,
                         viewsets.GenericViewSet,
                         dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.AppAnalysisSerializer
    queryset = App_Analysis.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiAppAnalysisFilter
    swagger_schema = prefetch.get_prefetch_schema(["technologies_list", "technologies_read"], serializers.AppAnalysisSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasAppAnalysisPermission)

    def get_queryset(self):
        return get_authorized_app_analysis(Permissions.Product_View)


# Authorization: object-based
class CredentialsViewSet(prefetch.PrefetchListMixin,
                         prefetch.PrefetchRetrieveMixin,
                         mixins.ListModelMixin,
                         mixins.RetrieveModelMixin,
                         mixins.UpdateModelMixin,
                         mixins.DestroyModelMixin,
                         mixins.CreateModelMixin,
                         viewsets.GenericViewSet,
                         dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.CredentialSerializer
    queryset = Cred_User.objects.all()
    filter_backends = (DjangoFilterBackend,)
    swagger_schema = prefetch.get_prefetch_schema(["credentials_list", "credentials_read"], serializers.CredentialSerializer).to_schema()
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)


# Authorization: configuration
class CredentialsMappingViewSet(prefetch.PrefetchListMixin,
                                prefetch.PrefetchRetrieveMixin,
                                mixins.ListModelMixin,
                                mixins.RetrieveModelMixin,
                                mixins.UpdateModelMixin,
                                mixins.DestroyModelMixin,
                                mixins.CreateModelMixin,
                                viewsets.GenericViewSet,
                                dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.CredentialMappingSerializer
    queryset = Cred_Mapping.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiCredentialsFilter
    swagger_schema = prefetch.get_prefetch_schema(["credential_mappings_list", "credential_mappings_read"], serializers.CredentialMappingSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasCredentialPermission)

    def get_queryset(self):
        return get_authorized_cred_mappings(Permissions.Credential_View)


# Authorization: configuration
class FindingTemplatesViewSet(mixins.ListModelMixin,
                              mixins.RetrieveModelMixin,
                              mixins.UpdateModelMixin,
                              mixins.CreateModelMixin,
                              mixins.DestroyModelMixin,
                              viewsets.GenericViewSet,
                              dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.FindingTemplateSerializer
    queryset = Finding_Template.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiTemplateFindingFilter
    permission_classes = (permissions.UserHasConfigurationPermissionStaff, )


# Authorization: object-based
@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("related_fields", OpenApiTypes.BOOL, OpenApiParameter.QUERY, required=False,
                                description="Expand finding external relations (engagement, environment, product, \
                                            product_type, test, test_type)"),
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("related_fields", OpenApiTypes.BOOL, OpenApiParameter.QUERY, required=False,
                                description="Expand finding external relations (engagement, environment, product, \
                                            product_type, test, test_type)"),
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class FindingViewSet(prefetch.PrefetchListMixin,
                     prefetch.PrefetchRetrieveMixin,
                     mixins.UpdateModelMixin,
                     mixins.DestroyModelMixin,
                     mixins.CreateModelMixin,
                     ra_api.AcceptedFindingsMixin,
                     viewsets.GenericViewSet,
                     dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.FindingSerializer
    queryset = Finding.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiFindingFilter
    permission_classes = (IsAuthenticated, permissions.UserHasFindingPermission)

    _related_field_parameters = [openapi.Parameter(
                name="related_fields",
                in_=openapi.IN_QUERY,
                description="Expand finding external relations (engagement, environment, product, product_type, test, test_type)",
                type=openapi.TYPE_BOOLEAN)]
    swagger_schema = prefetch.get_prefetch_schema(["findings_list", "findings_read"], serializers.FindingSerializer). \
        composeWith(schema.ExtraParameters("findings_list", _related_field_parameters)). \
        composeWith(schema.ExtraParameters("findings_read", _related_field_parameters)). \
        to_schema()

    # Overriding mixins.UpdateModeMixin perform_update() method to grab push_to_jira
    # data and add that as a parameter to .save()
    def perform_update(self, serializer):
        # IF JIRA is enabled and this product has a JIRA configuration
        push_to_jira = serializer.validated_data.get('push_to_jira')
        jira_project = jira_helper.get_jira_project(serializer.instance)
        if get_system_setting('enable_jira') and jira_project:
            push_to_jira = push_to_jira or jira_project.push_all_issues

        serializer.save(push_to_jira=push_to_jira)

    def get_queryset(self):
        findings = get_authorized_findings(Permissions.Finding_View).prefetch_related('endpoints',
                                                    'reviewers',
                                                    'found_by',
                                                    'notes',
                                                    'risk_acceptance_set',
                                                    'test',
                                                    'tags',
                                                    'jira_issue',
                                                    'finding_group_set',
                                                    'files',
                                                    'burprawrequestresponse_set',
                                                    'status_finding',
                                                    'finding_meta',
                                                    'test__test_type',
                                                    'test__engagement',
                                                    'test__environment',
                                                    'test__engagement__product',
                                                    'test__engagement__product__prod_type')

        return findings.distinct()

    def get_serializer_class(self):
        if self.request and self.request.method == 'POST':
            return serializers.FindingCreateSerializer
        else:
            return serializers.FindingSerializer

    @extend_schema(
        methods=['POST'],
        request=serializers.FindingCloseSerializer,
        responses={status.HTTP_200_OK: serializers.FindingCloseSerializer}
    )
    @swagger_auto_schema(
        method='post',
        request_body=serializers.FindingCloseSerializer,
        responses={status.HTTP_200_OK: serializers.FindingCloseSerializer}
    )
    @action(detail=True, methods=["post"])
    def close(self, request, pk=None):
        finding = self.get_object()

        if request.method == 'POST':
            finding_close = serializers.FindingCloseSerializer(data=request.data)
            if finding_close.is_valid():
                finding.is_mitigated = finding_close.validated_data['is_mitigated']
                if settings.EDITABLE_MITIGATED_DATA:
                    finding.mitigated = finding_close.validated_data['mitigated'] or timezone.now()
                else:
                    finding.mitigated = timezone.now()
                finding.mitigated_by = request.user
                finding.active = False
                finding.false_p = finding_close.validated_data.get('false_p', False)
                finding.duplicate = finding_close.validated_data.get('duplicate', False)
                finding.out_of_scope = finding_close.validated_data.get('out_of_scope', False)

                endpoints_status = finding.status_finding.all()
                for e_status in endpoints_status:
                    e_status.mitigated_by = request.user
                    if settings.EDITABLE_MITIGATED_DATA:
                        e_status.mitigated_time = finding_close.validated_data["mitigated"] or timezone.now()
                    else:
                        e_status.mitigated_time = timezone.now()
                    e_status.mitigated = True
                    e_status.last_modified = timezone.now()
                    e_status.save()
                finding.save()
            else:
                return Response(finding_close.errors,
                    status=status.HTTP_400_BAD_REQUEST)
        serialized_finding = serializers.FindingCloseSerializer(finding)
        return Response(serialized_finding.data)

    @extend_schema(
        methods=['GET'],
        responses={status.HTTP_200_OK: serializers.TagSerializer}
    )
    @extend_schema(
        methods=['POST'],
        request=serializers.TagSerializer,
        responses={status.HTTP_201_CREATED: serializers.TagSerializer}
    )
    @swagger_auto_schema(
        method='get',
        responses={status.HTTP_200_OK: serializers.TagSerializer}
    )
    @swagger_auto_schema(
        method='post',
        request_body=serializers.TagSerializer,
        responses={status.HTTP_200_OK: serializers.TagSerializer}
    )
    @action(detail=True, methods=['get', 'post'])
    def tags(self, request, pk=None):
        finding = self.get_object()

        if request.method == 'POST':
            new_tags = serializers.TagSerializer(data=request.data)
            if new_tags.is_valid():
                all_tags = finding.tags
                all_tags = serializers.TagSerializer({"tags": all_tags}).data['tags']

                for tag in tagulous.utils.parse_tags(new_tags.validated_data['tags']):
                    if tag not in all_tags:
                        all_tags.append(tag)
                new_tags = tagulous.utils.render_tags(all_tags)
                finding.tags = new_tags
                finding.save()
            else:
                return Response(new_tags.errors,
                    status=status.HTTP_400_BAD_REQUEST)
        tags = finding.tags
        serialized_tags = serializers.TagSerializer({"tags": tags})
        return Response(serialized_tags.data)

    @extend_schema(
        methods=['GET'],
        responses={status.HTTP_200_OK: serializers.BurpRawRequestResponseSerializer}
    )
    @extend_schema(
        methods=['POST'],
        request=serializers.BurpRawRequestResponseSerializer,
        responses={status.HTTP_201_CREATED: serializers.BurpRawRequestResponseSerializer}
    )
    @swagger_auto_schema(
        method='get',
        responses={status.HTTP_200_OK: serializers.BurpRawRequestResponseSerializer}
    )
    @swagger_auto_schema(
        method='post',
        request_body=serializers.BurpRawRequestResponseSerializer,
        responses={status.HTTP_200_OK: serializers.BurpRawRequestResponseSerializer}
    )
    @action(detail=True, methods=['get', 'post'])
    def request_response(self, request, pk=None):
        finding = self.get_object()

        if request.method == 'POST':
            burps = serializers.BurpRawRequestResponseSerializer(data=request.data, many=isinstance(request.data, list))
            if burps.is_valid():
                for pair in burps.validated_data['req_resp']:
                    burp_rr = BurpRawRequestResponse(
                                    finding=finding,
                                    burpRequestBase64=base64.b64encode(pair["request"].encode("utf-8")),
                                    burpResponseBase64=base64.b64encode(pair["response"].encode("utf-8")),
                                )
                    burp_rr.clean()
                    burp_rr.save()
            else:
                return Response(burps.errors,
                    status=status.HTTP_400_BAD_REQUEST)

        burp_req_resp = BurpRawRequestResponse.objects.filter(finding=finding)
        burp_list = []
        for burp in burp_req_resp:
            request = burp.get_request()
            response = burp.get_response()
            burp_list.append({'request': request, 'response': response})
        serialized_burps = serializers.BurpRawRequestResponseSerializer({'req_resp': burp_list})
        return Response(serialized_burps.data)

    @extend_schema(
        methods=['GET'],
        responses={status.HTTP_200_OK: serializers.FindingToNotesSerializer}
    )
    @extend_schema(
        methods=['POST'],
        request=serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.NoteSerializer}
    )
    @swagger_auto_schema(
        method='get',
        responses={status.HTTP_200_OK: serializers.FindingToNotesSerializer}
    )
    @swagger_auto_schema(
        methods=['post'],
        request_body=serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.NoteSerializer}
    )
    @action(detail=True, methods=["get", "post"])
    def notes(self, request, pk=None):
        finding = self.get_object()
        if request.method == 'POST':
            new_note = serializers.AddNewNoteOptionSerializer(data=request.data)
            if new_note.is_valid():
                entry = new_note.validated_data['entry']
                private = new_note.validated_data.get('private', False)
                note_type = new_note.validated_data.get('note_type', None)
            else:
                return Response(new_note.errors,
                    status=status.HTTP_400_BAD_REQUEST)

            author = request.user
            note = Notes(entry=entry, author=author, private=private, note_type=note_type)
            note.save()
            finding.notes.add(note)

            if finding.has_jira_issue:
                jira_helper.add_comment(finding, note)
            elif finding.has_jira_group_issue:
                jira_helper.add_comment(finding.finding_group, note)

            serialized_note = serializers.NoteSerializer({
                "author": author, "entry": entry,
                "private": private
            })
            result = serializers.FindingToNotesSerializer({
                "finding_id": finding, "notes": [serialized_note.data]
            })
            return Response(serialized_note.data,
                status=status.HTTP_201_CREATED)
        notes = finding.notes.all()

        serialized_notes = serializers.FindingToNotesSerializer({
                "finding_id": finding, "notes": notes
        })
        return Response(serialized_notes.data,
                status=status.HTTP_200_OK)

    @extend_schema(
        methods=['GET'],
        responses={status.HTTP_200_OK: serializers.FindingToFilesSerializer}
    )
    @extend_schema(
        methods=['POST'],
        request=serializers.AddNewFileOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.FileSerializer}
    )
    @swagger_auto_schema(
        method='get',
        responses={status.HTTP_200_OK: serializers.FindingToFilesSerializer}
    )
    @swagger_auto_schema(
        method='post',
        request_body=serializers.AddNewFileOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.FileSerializer}
    )
    @action(detail=True, methods=["get", "post"], parser_classes=(MultiPartParser,))
    def files(self, request, pk=None):
        finding = self.get_object()
        if request.method == 'POST':
            new_file = serializers.FileSerializer(data=request.data)
            if new_file.is_valid():
                title = new_file.validated_data['title']
                file = new_file.validated_data['file']
            else:
                return Response(new_file.errors, status=status.HTTP_400_BAD_REQUEST)

            file = FileUpload(title=title, file=file)
            file.save()
            finding.files.add(file)

            serialized_file = serializers.FileSerializer(file)
            return Response(serialized_file.data, status=status.HTTP_201_CREATED)

        files = finding.files.all()
        serialized_files = serializers.FindingToFilesSerializer({
            "finding_id": finding, "files": files
        })
        return Response(serialized_files.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=['GET'],
        responses={
            status.HTTP_200_OK: serializers.RawFileSerializer,
        }
    )
    @swagger_auto_schema(
        method='get',
        responses={
            status.HTTP_200_OK: serializers.RawFileSerializer,
        }
    )
    @action(detail=True, methods=["get"], url_path=r'files/download/(?P<file_id>\d+)')
    def download_file(self, request, file_id, pk=None):
        finding = self.get_object()
        # Get the file object
        file_object_qs = finding.files.filter(id=file_id)
        file_object = file_object_qs.first() if len(file_object_qs) > 0 else None
        if file_object is None:
            return Response({"error": "File ID not associated with Finding"}, status=status.HTTP_404_NOT_FOUND)
        # Get the path of the file in media root
        file_path = f'{settings.MEDIA_ROOT}/{file_object.file.url.lstrip(settings.MEDIA_URL)}'
        file_handle = open(file_path, "rb")
        # send file
        response = FileResponse(file_handle, content_type=f'{mimetypes.guess_type(file_path)}', status=status.HTTP_200_OK)
        response['Content-Length'] = file_object.file.size
        response['Content-Disposition'] = f'attachment; filename="{file_object.file.name}"'

        return response

    @extend_schema(
        request=serializers.FindingNoteSerializer,
        responses={status.HTTP_204_NO_CONTENT: ""}
    )
    @swagger_auto_schema(
        request_body=serializers.FindingNoteSerializer,
        responses={status.HTTP_204_NO_CONTENT: ""}
    )
    @action(detail=True, methods=["patch"])
    def remove_note(self, request, pk=None):
        """Remove Note From Finding Note"""
        finding = self.get_object()
        notes = finding.notes.all()
        if request.data['note_id']:
            note = get_object_or_404(Notes.objects, id=request.data['note_id'])
            if note not in notes:
                return Response({"error": "Selected Note is not assigned to this Finding"},
                status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"error": "('note_id') parameter missing"},
                status=status.HTTP_400_BAD_REQUEST)
        if note.author.username == request.user.username or request.user.is_superuser:
            finding.notes.remove(note)
            note.delete()
        else:
            return Response({"error": "Delete Failed, You are not the Note's author"},
                status=status.HTTP_400_BAD_REQUEST)

        return Response({"Success": "Selected Note has been Removed successfully"},
            status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        methods=['PUT', 'PATCH'],
        request=serializers.TagSerializer,
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @swagger_auto_schema(
        methods=['put', 'patch'],
        request_body=serializers.TagSerializer,
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @action(detail=True, methods=["put", "patch"])
    def remove_tags(self, request, pk=None):
        """ Remove Tag(s) from finding list of tags """
        finding = self.get_object()
        delete_tags = serializers.TagSerializer(data=request.data)
        if delete_tags.is_valid():
            all_tags = finding.tags
            all_tags = serializers.TagSerializer({"tags": all_tags}).data['tags']

            # serializer turns it into a string, but we need a list
            del_tags = tagulous.utils.parse_tags(delete_tags.validated_data['tags'])
            if len(del_tags) < 1:
                return Response({"error": "Empty Tag List Not Allowed"},
                        status=status.HTTP_400_BAD_REQUEST)
            for tag in del_tags:
                if tag not in all_tags:
                    return Response({"error": "'{}' is not a valid tag in list".format(tag)},
                        status=status.HTTP_400_BAD_REQUEST)
                all_tags.remove(tag)
            new_tags = tagulous.utils.render_tags(all_tags)
            finding.tags = new_tags
            finding.save()
            return Response({"success": "Tag(s) Removed"},
                status=status.HTTP_204_NO_CONTENT)
        else:
            return Response(delete_tags.errors,
                status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        responses={status.HTTP_200_OK: serializers.FindingSerializer(many=True)}
    )
    @swagger_auto_schema(
        responses={status.HTTP_200_OK: serializers.FindingSerializer(many=True)}
    )
    @action(detail=True, methods=['get'], url_path=r'duplicate', filter_backends=[], pagination_class=None)
    def get_duplicate_cluster(self, request, pk):
        finding = self.get_object()
        result = duplicate_cluster(request, finding)
        serializer = serializers.FindingSerializer(instance=result, many=True,
                                                   context={"request": request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        request=OpenApiTypes.NONE,
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @swagger_auto_schema(
        request_body=no_body,
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @action(detail=True, methods=['post'], url_path=r'duplicate/reset')
    def reset_finding_duplicate_status(self, request, pk):
        finding = self.get_object()
        checked_duplicate_id = reset_finding_duplicate_status_internal(request.user, pk)
        if checked_duplicate_id is None:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        request=OpenApiTypes.NONE,
        parameters=[
            OpenApiParameter("new_fid", OpenApiTypes.INT, OpenApiParameter.PATH)
        ],
        responses={status.HTTP_204_NO_CONTENT: ""},
    )
    @swagger_auto_schema(
        responses={status.HTTP_204_NO_CONTENT: ""},
        request_body=no_body
    )
    @action(detail=True, methods=['post'], url_path=r'original/(?P<new_fid>\d+)')
    def set_finding_as_original(self, request, pk, new_fid):
        finding = self.get_object()
        success = set_finding_as_original_internal(request.user, pk, new_fid)
        if not success:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @swagger_auto_schema(
        request_body=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def generate_report(self, request):
        findings = self.get_queryset()
        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(data=request.data)
        if report_options.is_valid():
            options['include_finding_notes'] = report_options.validated_data['include_finding_notes']
            options['include_finding_images'] = report_options.validated_data['include_finding_images']
            options['include_executive_summary'] = report_options.validated_data['include_executive_summary']
            options['include_table_of_contents'] = report_options.validated_data['include_table_of_contents']
        else:
            return Response(report_options.errors,
                status=status.HTTP_400_BAD_REQUEST)

        data = report_generate(request, findings, options)
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)

    def _get_metadata(self, request, finding):
        metadata = DojoMeta.objects.filter(finding=finding)
        serializer = serializers.FindingMetaSerializer(instance=metadata, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def _edit_metadata(self, request, finding):
        metadata_name = request.query_params.get("name", None)
        if metadata_name is None:
            return Response("Metadata name is required", status=status.HTTP_400_BAD_REQUEST)

        try:
            DojoMeta.objects.update_or_create(
                name=metadata_name, finding=finding,
                defaults={
                    "name": request.data.get("name"),
                    "value": request.data.get("value")
                }
            )

            return Response(data=request.data, status=status.HTTP_200_OK)
        except IntegrityError:
            return Response("Update failed because the new name already exists",
                status=status.HTTP_400_BAD_REQUEST)

    def _add_metadata(self, request, finding):
        metadata_data = serializers.FindingMetaSerializer(data=request.data)

        if metadata_data.is_valid():
            name = metadata_data.validated_data["name"]
            value = metadata_data.validated_data["value"]

            metadata = DojoMeta(finding=finding, name=name, value=value)
            try:
                metadata.validate_unique()
                metadata.save()
            except ValidationError:
                return Response("Create failed probably because the name of the metadata already exists", status=status.HTTP_400_BAD_REQUEST)

            return Response(data=metadata_data.data, status=status.HTTP_200_OK)
        else:
            return Response(metadata_data.errors,
                status=status.HTTP_400_BAD_REQUEST)

    def _remove_metadata(self, request, finding):
        name = request.query_params.get("name", None)
        if name is None:
            return Response("A metadata name must be provided", status=status.HTTP_400_BAD_REQUEST)

        metadata = get_object_or_404(DojoMeta.objects, finding=finding, name=name)
        metadata.delete()

        return Response("Metadata deleted", status=status.HTTP_200_OK)

    @extend_schema(
        methods=['GET'],
        responses={
            status.HTTP_200_OK: serializers.FindingMetaSerializer(many=True),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description="Returned if finding does not exist"),
        },
    )
    @extend_schema(
        methods=['DELETE'],
        parameters=[
            OpenApiParameter("name", OpenApiTypes.INT, OpenApiParameter.QUERY, required=True,
                                description="name of the metadata to retrieve. If name is empty, return all the \
                                    metadata associated with the finding")
        ],
        responses={
            status.HTTP_200_OK: OpenApiResponse(description="Returned if the metadata was correctly deleted"),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description="Returned if finding does not exist"),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description="Returned if there was a problem with the metadata information"),
        },
        # manual_parameters=[openapi.Parameter(
        #     name="name", in_=openapi.IN_QUERY,  type=openapi.TYPE_STRING,
        #     description="name of the metadata to retrieve. If name is empty, return all the \
        #                     metadata associated with the finding")]
    )
    @extend_schema(
        methods=['PUT'],
        request=serializers.FindingMetaSerializer,
        responses={
            status.HTTP_200_OK: serializers.FindingMetaSerializer,
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description="Returned if finding does not exist"),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description="Returned if there was a problem with the metadata information"),
        },
        # manual_parameters=[openapi.Parameter(
        #     name="name", in_=openapi.IN_QUERY, required=True, type=openapi.TYPE_STRING,
        #     description="name of the metadata to edit")],
    )
    @extend_schema(
        methods=['POST'],
        request=serializers.FindingMetaSerializer,
        responses={
            status.HTTP_200_OK: serializers.FindingMetaSerializer,
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description="Returned if finding does not exist"),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description="Returned if there was a problem with the metadata information"),
        },
    )
    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK: serializers.FindingMetaSerializer(many=True),
            status.HTTP_404_NOT_FOUND: "Returned if finding does not exist"
        },
        methods=['get']
    )
    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK: "Returned if the metadata was correctly deleted",
            status.HTTP_404_NOT_FOUND: "Returned if finding does not exist",
            status.HTTP_400_BAD_REQUEST: "Returned if there was a problem with the metadata information"
        },
        methods=['delete'],
        manual_parameters=[openapi.Parameter(
            name="name", in_=openapi.IN_QUERY, required=True, type=openapi.TYPE_STRING,
            description="name of the metadata to retrieve. If name is empty, return all the \
                            metadata associated with the finding")]
    )
    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK: serializers.FindingMetaSerializer,
            status.HTTP_404_NOT_FOUND: "Returned if finding does not exist",
            status.HTTP_400_BAD_REQUEST: "Returned if there was a problem with the metadata information"
        },
        methods=['put'],
        manual_parameters=[openapi.Parameter(
            name="name", in_=openapi.IN_QUERY, required=True, type=openapi.TYPE_STRING,
            description="name of the metadata to edit")],
        request_body=serializers.FindingMetaSerializer
    )
    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK: serializers.FindingMetaSerializer,
            status.HTTP_404_NOT_FOUND: "Returned if finding does not exist",
            status.HTTP_400_BAD_REQUEST: "Returned if there was a problem with the metadata information"
        },
        methods=['post'],
        request_body=serializers.FindingMetaSerializer
    )
    @action(detail=True, methods=["post", "put", "delete", "get"],
            filter_backends=[], pagination_class=None)
    def metadata(self, request, pk=None):
        finding = self.get_object()

        if request.method == "GET":
            return self._get_metadata(request, finding)
        elif request.method == "POST":
            return self._add_metadata(request, finding)
        elif request.method == "PUT":
            return self._edit_metadata(request, finding)
        elif request.method == "PATCH":
            return self._edit_metadata(request, finding)
        elif request.method == "DELETE":
            return self._remove_metadata(request, finding)

        return Response({"error", "unsupported method"}, status=status.HTTP_400_BAD_REQUEST)


# Authorization: configuration
class JiraInstanceViewSet(mixins.ListModelMixin,
                                mixins.RetrieveModelMixin,
                                mixins.DestroyModelMixin,
                                mixins.UpdateModelMixin,
                                mixins.CreateModelMixin,
                                viewsets.GenericViewSet,
                                dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.JIRAInstanceSerializer
    queryset = JIRA_Instance.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'url')
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser, )


# Authorization: object-based
class JiraIssuesViewSet(prefetch.PrefetchListMixin,
                        prefetch.PrefetchRetrieveMixin,
                        mixins.ListModelMixin,
                        mixins.RetrieveModelMixin,
                        mixins.DestroyModelMixin,
                        mixins.CreateModelMixin,
                        mixins.UpdateModelMixin,
                        viewsets.GenericViewSet,
                        dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.JIRAIssueSerializer
    queryset = JIRA_Issue.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'jira_id', 'jira_key', 'finding', 'engagement', 'finding_group')
    swagger_schema = prefetch.get_prefetch_schema(["jira_finding_mappings_list", "jira_finding_mappings_read"], serializers.JIRAIssueSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasJiraIssuePermission)

    def get_queryset(self):
        return get_authorized_jira_issues(Permissions.Product_View)


# Authorization: object-based
class JiraProjectViewSet(prefetch.PrefetchListMixin,
                         prefetch.PrefetchRetrieveMixin,
                         mixins.ListModelMixin,
                         mixins.RetrieveModelMixin,
                         mixins.DestroyModelMixin,
                         mixins.UpdateModelMixin,
                         mixins.CreateModelMixin,
                         viewsets.GenericViewSet,
                         dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.JIRAProjectSerializer
    queryset = JIRA_Project.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = (
        'id', 'jira_instance', 'product', 'engagement', 'component', 'project_key',
        'push_all_issues', 'enable_engagement_epic_mapping', 'push_notes')
    swagger_schema = prefetch.get_prefetch_schema(["jira_projects_list", "jira_projects_read"], serializers.JIRAProjectSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasJiraProductPermission)

    def get_queryset(self):
        return get_authorized_jira_projects(Permissions.Product_View)


# Authorization: superuser
class SonarqubeIssueViewSet(mixins.ListModelMixin,
                                mixins.RetrieveModelMixin,
                                mixins.DestroyModelMixin,
                                mixins.UpdateModelMixin,
                                mixins.CreateModelMixin,
                                viewsets.GenericViewSet,
                                dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.SonarqubeIssueSerializer
    queryset = Sonarqube_Issue.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'key', 'status', 'type')
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)


# Authorization: superuser
class SonarqubeIssueTransitionViewSet(mixins.ListModelMixin,
                        mixins.RetrieveModelMixin,
                        mixins.DestroyModelMixin,
                        mixins.CreateModelMixin,
                        mixins.UpdateModelMixin,
                        viewsets.GenericViewSet,
                        dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.SonarqubeIssueTransitionSerializer
    queryset = Sonarqube_Issue_Transition.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'sonarqube_issue', 'finding_status',
                     'sonarqube_status', 'transitions')
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)


# Authorization: object-based
class ProductAPIScanConfigurationViewSet(prefetch.PrefetchListMixin,
                                         prefetch.PrefetchRetrieveMixin,
                                         mixins.ListModelMixin,
                                         mixins.RetrieveModelMixin,
                                         mixins.DestroyModelMixin,
                                         mixins.UpdateModelMixin,
                                         mixins.CreateModelMixin,
                                         viewsets.GenericViewSet,
                                         dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.ProductAPIScanConfigurationSerializer
    queryset = Product_API_Scan_Configuration.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'product', 'tool_configuration', 'service_key_1', 'service_key_2', 'service_key_3')
    swagger_schema = prefetch.get_prefetch_schema(["product_api_scan_configurations_list", "product_api_scan_configurations_read"], serializers.ProductAPIScanConfigurationSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasProductAPIScanConfigurationPermission)

    def get_queryset(self):
        return get_authorized_product_api_scan_configurations(Permissions.Product_API_Scan_Configuration_View)


# Authorization: object-based
@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class DojoMetaViewSet(prefetch.PrefetchListMixin,
                      prefetch.PrefetchRetrieveMixin,
                      mixins.ListModelMixin,
                      mixins.RetrieveModelMixin,
                      mixins.DestroyModelMixin,
                      mixins.CreateModelMixin,
                      mixins.UpdateModelMixin,
                      viewsets.GenericViewSet,
                      dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.MetaSerializer
    queryset = DojoMeta.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'product', 'endpoint', 'finding', 'name', 'value')
    permission_classes = (IsAuthenticated, permissions.UserHasDojoMetaPermission)
    swagger_schema = prefetch.get_prefetch_schema(["metadata_list", "metadata_read"],
        serializers.MetaSerializer).to_schema()

    def get_queryset(self):
        return get_authorized_dojo_meta(Permissions.Product_View)


# Authorization: object-based
class DjangoFilterDescriptionInspector(CoreAPICompatInspector):
    def get_filter_parameters(self, filter_backend):
        if isinstance(filter_backend, DjangoFilterBackend):
            result = super(DjangoFilterDescriptionInspector, self).get_filter_parameters(filter_backend)
            for param in result:
                if not param.get('description', ''):
                    param.description = "Filter the returned list by {field_name}".format(field_name=param.name)

            return result

        return NotHandled


@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
@method_decorator(name='list', decorator=swagger_auto_schema(
    filter_inspectors=[DjangoFilterDescriptionInspector]
))
class ProductViewSet(prefetch.PrefetchListMixin,
                     prefetch.PrefetchRetrieveMixin,
                     mixins.CreateModelMixin,
                     mixins.DestroyModelMixin,
                     mixins.UpdateModelMixin,
                     viewsets.GenericViewSet,
                     dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.ProductSerializer
    # TODO: prefetch
    queryset = Product.objects.none()
    filter_backends = (DjangoFilterBackend,)

    filterset_class = ApiProductFilter
    swagger_schema = prefetch.get_prefetch_schema(["products_list", "products_read"], serializers.ProductSerializer). \
        to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasProductPermission)

    def get_queryset(self):
        return get_authorized_products(Permissions.Product_View).distinct()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if get_setting("ASYNC_OBJECT_DELETE"):
            async_del = async_delete()
            async_del.delete(instance)
        else:
            instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    # def list(self, request):
    #     print(vars(request))
    #     # Note the use of `get_queryset()` instead of `self.queryset`
    #     queryset = self.get_queryset()
    #     serializer = self.serializer_class(queryset, many=True)
    #     return Response(serializer.data)

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @swagger_auto_schema(
        request_body=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def generate_report(self, request, pk=None):
        product = self.get_object()

        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(data=request.data)
        if report_options.is_valid():
            options['include_finding_notes'] = report_options.validated_data['include_finding_notes']
            options['include_finding_images'] = report_options.validated_data['include_finding_images']
            options['include_executive_summary'] = report_options.validated_data['include_executive_summary']
            options['include_table_of_contents'] = report_options.validated_data['include_table_of_contents']
        else:
            return Response(report_options.errors,
                status=status.HTTP_400_BAD_REQUEST)

        data = report_generate(request, product, options)
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)


# Authorization: object-based
@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class ProductMemberViewSet(prefetch.PrefetchListMixin,
                           prefetch.PrefetchRetrieveMixin,
                           mixins.ListModelMixin,
                           mixins.RetrieveModelMixin,
                           mixins.CreateModelMixin,
                           mixins.DestroyModelMixin,
                           mixins.UpdateModelMixin,
                           viewsets.GenericViewSet,
                           dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.ProductMemberSerializer
    queryset = Product_Member.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'product_id', 'user_id')
    swagger_schema = prefetch.get_prefetch_schema(["product_members_list", "product_members_read"],
        serializers.ProductMemberSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasProductMemberPermission)

    def get_queryset(self):
        return get_authorized_product_members(Permissions.Product_View).distinct()

    @extend_schema(
        request=OpenApiTypes.NONE,
        responses={status.HTTP_405_METHOD_NOT_ALLOWED: ""},
    )
    @swagger_auto_schema(
        request_body=no_body,
        responses={status.HTTP_405_METHOD_NOT_ALLOWED: ""},
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {'message': 'Patch function is not offered in this path.'}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Authorization: object-based
@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class ProductGroupViewSet(prefetch.PrefetchListMixin,
                          prefetch.PrefetchRetrieveMixin,
                          mixins.ListModelMixin,
                          mixins.RetrieveModelMixin,
                          mixins.CreateModelMixin,
                          mixins.DestroyModelMixin,
                          mixins.UpdateModelMixin,
                          viewsets.GenericViewSet,
                          dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.ProductGroupSerializer
    queryset = Product_Group.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'product_id', 'group_id')
    swagger_schema = prefetch.get_prefetch_schema(["product_groups_list", "product_groups_read"],
        serializers.ProductGroupSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasProductGroupPermission)

    def get_queryset(self):
        return get_authorized_product_groups(Permissions.Product_Group_View).distinct()

    @extend_schema(
        request=OpenApiTypes.NONE,
        responses={status.HTTP_405_METHOD_NOT_ALLOWED: ""},
    )
    @swagger_auto_schema(
        request_body=no_body,
        responses={status.HTTP_405_METHOD_NOT_ALLOWED: ""},
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {'message': 'Patch function is not offered in this path.'}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Authorization: object-based
@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class ProductTypeViewSet(prefetch.PrefetchListMixin,
                         prefetch.PrefetchRetrieveMixin,
                         mixins.ListModelMixin,
                         mixins.RetrieveModelMixin,
                         mixins.CreateModelMixin,
                         mixins.UpdateModelMixin,
                         mixins.DestroyModelMixin,
                         viewsets.GenericViewSet,
                         dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.ProductTypeSerializer
    queryset = Product_Type.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'name', 'critical_product', 'key_product', 'created', 'updated')
    swagger_schema = prefetch.get_prefetch_schema(["product_types_list", "product_types_read"],
        serializers.ProductTypeSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasProductTypePermission)

    def get_queryset(self):
        return get_authorized_product_types(Permissions.Product_Type_View).distinct()

    # Overwrite perfom_create of CreateModelMixin to add current user as owner
    def perform_create(self, serializer):
        serializer.save()
        product_type_data = serializer.data
        product_type_data.pop('authorization_groups')
        product_type_data.pop('members')
        member = Product_Type_Member()
        member.user = self.request.user
        member.product_type = Product_Type(**product_type_data)
        member.role = Role.objects.get(is_owner=True)
        member.save()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if get_setting("ASYNC_OBJECT_DELETE"):
            async_del = async_delete()
            async_del.delete(instance)
        else:
            instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @swagger_auto_schema(
        request_body=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def generate_report(self, request, pk=None):
        product_type = self.get_object()

        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(data=request.data)
        if report_options.is_valid():
            options['include_finding_notes'] = report_options.validated_data['include_finding_notes']
            options['include_finding_images'] = report_options.validated_data['include_finding_images']
            options['include_executive_summary'] = report_options.validated_data['include_executive_summary']
            options['include_table_of_contents'] = report_options.validated_data['include_table_of_contents']
        else:
            return Response(report_options.errors,
                status=status.HTTP_400_BAD_REQUEST)

        data = report_generate(request, product_type, options)
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)


# Authorization: object-based
@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class ProductTypeMemberViewSet(prefetch.PrefetchListMixin,
                               prefetch.PrefetchRetrieveMixin,
                               mixins.ListModelMixin,
                               mixins.RetrieveModelMixin,
                               mixins.CreateModelMixin,
                               mixins.DestroyModelMixin,
                               mixins.UpdateModelMixin,
                               viewsets.GenericViewSet,
                               dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.ProductTypeMemberSerializer
    queryset = Product_Type_Member.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'product_type_id', 'user_id')
    swagger_schema = prefetch.get_prefetch_schema(["product_type_members_list", "product_type_members_read"],
        serializers.ProductTypeMemberSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasProductTypeMemberPermission)

    def get_queryset(self):
        return get_authorized_product_type_members(Permissions.Product_Type_View).distinct()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.role.is_owner:
            owners = Product_Type_Member.objects.filter(product_type=instance.product_type, role__is_owner=True).count()
            if owners <= 1:
                return Response('There must be at least one owner', status=status.HTTP_400_BAD_REQUEST)
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        request=OpenApiTypes.NONE,
        responses={status.HTTP_405_METHOD_NOT_ALLOWED: ""},
    )
    @swagger_auto_schema(
        request_body=no_body,
        responses={status.HTTP_405_METHOD_NOT_ALLOWED: ""},
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {'message': 'Patch function is not offered in this path.'}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Authorization: object-based
@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class ProductTypeGroupViewSet(prefetch.PrefetchListMixin,
                              prefetch.PrefetchRetrieveMixin,
                              mixins.ListModelMixin,
                              mixins.RetrieveModelMixin,
                              mixins.CreateModelMixin,
                              mixins.DestroyModelMixin,
                              mixins.UpdateModelMixin,
                              viewsets.GenericViewSet,
                              dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.ProductTypeGroupSerializer
    queryset = Product_Type_Group.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'product_type_id', 'group_id')
    swagger_schema = prefetch.get_prefetch_schema(["product_type_groups_list", "product_type_groups_read"],
        serializers.ProductTypeGroupSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasProductTypeGroupPermission)

    def get_queryset(self):
        return get_authorized_product_type_groups(Permissions.Product_Type_Group_View).distinct()

    @extend_schema(
        request=OpenApiTypes.NONE,
        responses={status.HTTP_405_METHOD_NOT_ALLOWED: ""},
    )
    @swagger_auto_schema(
        request_body=no_body,
        responses={status.HTTP_405_METHOD_NOT_ALLOWED: ""},
    )
    def partial_update(self, request, pk=None):
        # Object authorization won't work if not all data is provided
        response = {'message': 'Patch function is not offered in this path.'}
        return Response(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# Authorization: object-based
class StubFindingsViewSet(prefetch.PrefetchListMixin,
                          prefetch.PrefetchRetrieveMixin,
                          mixins.ListModelMixin,
                          mixins.RetrieveModelMixin,
                          mixins.CreateModelMixin,
                          mixins.UpdateModelMixin,
                          mixins.DestroyModelMixin,
                          viewsets.GenericViewSet,
                          dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.StubFindingSerializer
    queryset = Stub_Finding.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'title', 'date', 'severity', 'description')
    swagger_schema = prefetch.get_prefetch_schema(["stub_findings_list", "stub_findings_read"], serializers.StubFindingSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasFindingPermission)

    def get_queryset(self):
        return get_authorized_stub_findings(Permissions.Finding_View).distinct()

    def get_serializer_class(self):
        if self.request and self.request.method == 'POST':
            return serializers.StubFindingCreateSerializer
        else:
            return serializers.StubFindingSerializer


# Authorization: authenticated, configuration
class DevelopmentEnvironmentViewSet(mixins.ListModelMixin,
                                    mixins.RetrieveModelMixin,
                                    mixins.CreateModelMixin,
                                    mixins.DestroyModelMixin,
                                    mixins.UpdateModelMixin,
                                    viewsets.GenericViewSet,
                                    dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.DevelopmentEnvironmentSerializer
    queryset = Development_Environment.objects.all()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, DjangoModelPermissions)


# Authorization: object-based
class TestsViewSet(prefetch.PrefetchListMixin,
                   prefetch.PrefetchRetrieveMixin,
                   mixins.ListModelMixin,
                   mixins.RetrieveModelMixin,
                   mixins.UpdateModelMixin,
                   mixins.DestroyModelMixin,
                   mixins.CreateModelMixin,
                   ra_api.AcceptedRisksMixin,
                   viewsets.GenericViewSet,
                   dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.TestSerializer
    queryset = Test.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiTestFilter
    swagger_schema = prefetch.get_prefetch_schema(["tests_list", "tests_read"], serializers.TestSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasTestPermission)

    @property
    def risk_application_model_class(self):
        return Test

    def get_queryset(self):
        return get_authorized_tests(Permissions.Test_View).prefetch_related(
                                                'notes',
                                                'files').distinct()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if get_setting("ASYNC_OBJECT_DELETE"):
            async_del = async_delete()
            async_del.delete(instance)
        else:
            instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_serializer_class(self):
        if self.request and self.request.method == 'POST':
            if self.action == 'accept_risks':
                return ra_api.AcceptedRiskSerializer
            return serializers.TestCreateSerializer
        else:
            return serializers.TestSerializer

    @extend_schema(
        request=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @swagger_auto_schema(
        request_body=serializers.ReportGenerateOptionSerializer,
        responses={status.HTTP_200_OK: serializers.ReportGenerateSerializer},
    )
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def generate_report(self, request, pk=None):
        test = self.get_object()

        options = {}
        # prepare post data
        report_options = serializers.ReportGenerateOptionSerializer(data=request.data)
        if report_options.is_valid():
            options['include_finding_notes'] = report_options.validated_data['include_finding_notes']
            options['include_finding_images'] = report_options.validated_data['include_finding_images']
            options['include_executive_summary'] = report_options.validated_data['include_executive_summary']
            options['include_table_of_contents'] = report_options.validated_data['include_table_of_contents']
        else:
            return Response(report_options.errors,
                status=status.HTTP_400_BAD_REQUEST)

        data = report_generate(request, test, options)
        report = serializers.ReportGenerateSerializer(data)
        return Response(report.data)

    @extend_schema(
        methods=['GET'],
        responses={status.HTTP_200_OK: serializers.TestToNotesSerializer}
    )
    @extend_schema(
        methods=['POST'],
        request=serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.NoteSerializer}
    )
    @swagger_auto_schema(
        method='get',
        responses={status.HTTP_200_OK: serializers.TestToNotesSerializer}
    )
    @swagger_auto_schema(
        methods=['post'],
        request_body=serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.NoteSerializer}
    )
    @action(detail=True, methods=["get", "post"])
    def notes(self, request, pk=None):
        test = self.get_object()
        if request.method == 'POST':
            new_note = serializers.AddNewNoteOptionSerializer(data=request.data)
            if new_note.is_valid():
                entry = new_note.validated_data['entry']
                private = new_note.validated_data.get('private', False)
                note_type = new_note.validated_data.get('note_type', None)
            else:
                return Response(new_note.errors,
                    status=status.HTTP_400_BAD_REQUEST)

            author = request.user
            note = Notes(entry=entry, author=author, private=private, note_type=note_type)
            note.save()
            test.notes.add(note)

            serialized_note = serializers.NoteSerializer({
                "author": author, "entry": entry,
                "private": private
            })
            result = serializers.TestToNotesSerializer({
                "test_id": test, "notes": [serialized_note.data]
            })
            return Response(serialized_note.data,
                status=status.HTTP_201_CREATED)
        notes = test.notes.all()

        serialized_notes = serializers.TestToNotesSerializer({
                "test_id": test, "notes": notes
        })
        return Response(serialized_notes.data,
                status=status.HTTP_200_OK)

    @extend_schema(
        methods=['GET'],
        responses={status.HTTP_200_OK: serializers.TestToFilesSerializer}
    )
    @extend_schema(
        methods=['POST'],
        request=serializers.AddNewFileOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.FileSerializer}
    )
    @swagger_auto_schema(
        method='get',
        responses={status.HTTP_200_OK: serializers.TestToFilesSerializer}
    )
    @swagger_auto_schema(
        method='post',
        request_body=serializers.AddNewFileOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.FileSerializer}
    )
    @action(detail=True, methods=["get", "post"], parser_classes=(MultiPartParser,))
    def files(self, request, pk=None):
        test = self.get_object()
        if request.method == 'POST':
            new_file = serializers.FileSerializer(data=request.data)
            if new_file.is_valid():
                title = new_file.validated_data['title']
                file = new_file.validated_data['file']
            else:
                return Response(new_file.errors, status=status.HTTP_400_BAD_REQUEST)

            file = FileUpload(title=title, file=file)
            file.save()
            test.files.add(file)

            serialized_file = serializers.FileSerializer(file)
            return Response(serialized_file.data, status=status.HTTP_201_CREATED)

        files = test.files.all()
        serialized_files = serializers.TestToFilesSerializer({
            "test_id": test, "files": files
        })
        return Response(serialized_files.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=['GET'],
        responses={
            status.HTTP_200_OK: serializers.RawFileSerializer,
        }
    )
    @swagger_auto_schema(
        method='get',
        responses={
            status.HTTP_200_OK: serializers.RawFileSerializer,
        }
    )
    @action(detail=True, methods=["get"], url_path=r'files/download/(?P<file_id>\d+)')
    def download_file(self, request, file_id, pk=None):
        test = self.get_object()
        # Get the file object
        file_object_qs = test.files.filter(id=file_id)
        file_object = file_object_qs.first() if len(file_object_qs) > 0 else None
        if file_object is None:
            return Response({"error": "File ID not associated with Test"}, status=status.HTTP_404_NOT_FOUND)
        # Get the path of the file in media root
        file_path = f'{settings.MEDIA_ROOT}/{file_object.file.url.lstrip(settings.MEDIA_URL)}'
        file_handle = open(file_path, "rb")
        # send file
        response = FileResponse(file_handle, content_type=f'{mimetypes.guess_type(file_path)}', status=status.HTTP_200_OK)
        response['Content-Length'] = file_object.file.size
        response['Content-Disposition'] = f'attachment; filename="{file_object.file.name}"'

        return response


# Authorization: authenticated, configuration
class TestTypesViewSet(mixins.ListModelMixin,
                       mixins.RetrieveModelMixin,
                       mixins.UpdateModelMixin,
                       mixins.CreateModelMixin,
                       viewsets.GenericViewSet):
    serializer_class = serializers.TestTypeSerializer
    queryset = Test_Type.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('name',)
    permission_classes = (IsAuthenticated, DjangoModelPermissions)


@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class TestImportViewSet(prefetch.PrefetchListMixin,
                      prefetch.PrefetchRetrieveMixin,
                      mixins.ListModelMixin,
                      mixins.RetrieveModelMixin,
                      mixins.UpdateModelMixin,
                      mixins.CreateModelMixin,
                      mixins.DestroyModelMixin,
                      viewsets.GenericViewSet,
                      dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.TestImportSerializer
    queryset = Test_Import.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('test', 'findings_affected', 'version', 'branch_tag', 'build_id', 'commit_hash', 'test_import_finding_action__action',
                    'test_import_finding_action__finding', 'test_import_finding_action__created')
    swagger_schema = prefetch.get_prefetch_schema(["test_imports_list", "test_imports_read"], serializers.TestImportSerializer). \
        to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasTestImportPermission)

    def get_queryset(self):
        return get_authorized_test_imports(Permissions.Test_View).prefetch_related(
                                        'test_import_finding_action_set',
                                        'findings_affected',
                                        'findings_affected__endpoints',
                                        'findings_affected__status_finding',
                                        'findings_affected__finding_meta',
                                        'findings_affected__jira_issue',
                                        'findings_affected__burprawrequestresponse_set',
                                        'findings_affected__jira_issue',
                                        'findings_affected__jira_issue',
                                        'findings_affected__jira_issue',
                                        'findings_affected__reviewers',
                                        'findings_affected__notes',
                                        'findings_affected__notes__author',
                                        'findings_affected__notes__history',
                                        'findings_affected__files',
                                        'findings_affected__found_by',
                                        'findings_affected__tags',
                                        'findings_affected__risk_acceptance_set',
                                        'test',
                                        'test__tags',
                                        'test__notes',
                                        'test__notes__author',
                                        'test__files',
                                        'test__test_type',
                                        'test__engagement',
                                        'test__environment',
                                        'test__engagement__product',
                                        'test__engagement__product__prod_type')


# Authorization: configurations
class ToolConfigurationsViewSet(prefetch.PrefetchListMixin,
                                prefetch.PrefetchRetrieveMixin,
                                mixins.ListModelMixin,
                                mixins.RetrieveModelMixin,
                                mixins.CreateModelMixin,
                                mixins.UpdateModelMixin,
                                mixins.DestroyModelMixin,
                                viewsets.GenericViewSet,
                                dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.ToolConfigurationSerializer
    queryset = Tool_Configuration.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'name', 'tool_type', 'url', 'authentication_type')
    swagger_schema = prefetch.get_prefetch_schema(["tool_configurations_list", "tool_configurations_read"], serializers.ToolConfigurationSerializer).to_schema()
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser, )


# Authorization: object-based
class ToolProductSettingsViewSet(prefetch.PrefetchListMixin,
                                 prefetch.PrefetchRetrieveMixin,
                                 mixins.ListModelMixin,
                                 mixins.RetrieveModelMixin,
                                 mixins.DestroyModelMixin,
                                 mixins.CreateModelMixin,
                                 mixins.UpdateModelMixin,
                                 viewsets.GenericViewSet,
                                 dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.ToolProductSettingsSerializer
    queryset = Tool_Product_Settings.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'name', 'product', 'tool_configuration', 'tool_project_id', 'url')
    swagger_schema = prefetch.get_prefetch_schema(["tool_configurations_list", "tool_configurations_read"], serializers.ToolConfigurationSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasToolProductSettingsPermission)

    def get_queryset(self):
        return get_authorized_tool_product_settings(Permissions.Product_View)


# Authorization: configuration
class ToolTypesViewSet(mixins.ListModelMixin,
                       mixins.RetrieveModelMixin,
                       mixins.DestroyModelMixin,
                       mixins.CreateModelMixin,
                       mixins.UpdateModelMixin,
                       viewsets.GenericViewSet,
                       dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.ToolTypeSerializer
    queryset = Tool_Type.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'name', 'description')
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser, )


# Authorization: authenticated, configuration
class RegulationsViewSet(mixins.ListModelMixin,
                         mixins.RetrieveModelMixin,
                         mixins.CreateModelMixin,
                         mixins.DestroyModelMixin,
                         mixins.UpdateModelMixin,
                         viewsets.GenericViewSet,
                         dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.RegulationSerializer
    queryset = Regulation.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'name', 'description')
    permission_classes = (IsAuthenticated, DjangoModelPermissions)


# Authorization: configuration
class UsersViewSet(mixins.CreateModelMixin,
                   mixins.UpdateModelMixin,
                   mixins.ListModelMixin,
                   mixins.RetrieveModelMixin,
                   mixins.DestroyModelMixin,
                   viewsets.GenericViewSet,
                   dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.UserSerializer
    queryset = User.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'username', 'first_name', 'last_name', 'email', 'is_active', 'is_superuser')
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser, )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if request.user == instance:
            return Response('Users may not delete themselves', status=status.HTTP_400_BAD_REQUEST)
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


# Authorization: superuser
@extend_schema_view(
    list=extend_schema(parameters=[
        OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                         description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
        OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                         description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class UserContactInfoViewSet(prefetch.PrefetchListMixin,
                             prefetch.PrefetchRetrieveMixin,
                             mixins.CreateModelMixin,
                             mixins.UpdateModelMixin,
                             mixins.ListModelMixin,
                             mixins.RetrieveModelMixin,
                             mixins.DestroyModelMixin,
                             viewsets.GenericViewSet,
                             dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.UserContactInfoSerializer
    queryset = UserContactInfo.objects.all()
    swagger_schema = prefetch.get_prefetch_schema(["user_contact_infos_list", "user_contact_infos_read"],
                                                  serializers.UserContactInfoSerializer).to_schema()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = '__all__'
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)


# Authorization: authenticated users
class UserProfileView(GenericAPIView):
    permission_classes = (IsAuthenticated, )
    pagination_class = None
    serializer_class = serializers.UserProfileSerializer

    @swagger_auto_schema(
        method='get',
        responses={status.HTTP_200_OK: serializers.UserProfileSerializer}
    )
    @action(detail=True, methods=["get"],
            filter_backends=[], pagination_class=None)
    def get(self, request, format=None):
        user = get_current_user()
        user_contact_info = user.usercontactinfo if hasattr(user, 'usercontactinfo') else None
        global_role = user.global_role if hasattr(user, 'global_role') else None
        dojo_group_member = Dojo_Group_Member.objects.filter(user=user)
        product_type_member = Product_Type_Member.objects.filter(user=user)
        product_member = Product_Member.objects.filter(user=user)
        serializer = serializers.UserProfileSerializer(
            {"user": user,
             "user_contact_info": user_contact_info,
             "global_role": global_role,
             "dojo_group_member": dojo_group_member,
             "product_type_member": product_type_member,
             "product_member": product_member}, many=False)
        return Response(serializer.data)


# Authorization: authenticated users, DjangoModelPermissions
class ImportScanView(mixins.CreateModelMixin,
                     viewsets.GenericViewSet):
    """
    Imports a scan report into an engagement or product.

    By ID:
    - Create a Product (or use an existing product)
    - Create an Engagement inside the product
    - Provide the id of the engagement in the `engagement` parameter

    In this scenario a new Test will be created inside the engagement.

    By Names:
    - Create a Product (or use an existing product)
    - Create an Engagement inside the product
    - Provide `product_name`
    - Provide `engagement_name`
    - Optionally provide `product_type_name`

    In this scenario Defect Dojo will look up the Engagement by the provided details.

    When using names you can let the importer automatically create Engagements, Products and Product_Types
    by using `auto_create_context=True`.

    When `auto_create_context` is set to `True` you can use `deduplication_on_engagement` to restrict deduplication for
    imported Findings to the newly created Engagement.
    """
    serializer_class = serializers.ImportScanSerializer
    parser_classes = [MultiPartParser]
    queryset = Test.objects.none()
    permission_classes = (IsAuthenticated, permissions.UserHasImportPermission)

    def perform_create(self, serializer):
        _, _, _, engagement_id, engagement_name, product_name, product_type_name, auto_create_context, deduplication_on_engagement, do_not_reactivate = serializers.get_import_meta_data_from_dict(serializer.validated_data)
        product = get_target_product_if_exists(product_name)
        engagement = get_target_engagement_if_exists(engagement_id, engagement_name, product)

        # when using auto_create_context, the engagement or product may not have been created yet
        jira_driver = engagement if engagement else product if product else None
        jira_project = jira_helper.get_jira_project(jira_driver) if jira_driver else None

        push_to_jira = serializer.validated_data.get('push_to_jira')
        if get_system_setting('enable_jira') and jira_project:
            push_to_jira = push_to_jira or jira_project.push_all_issues

        logger.debug('push_to_jira: %s', serializer.validated_data.get('push_to_jira'))
        serializer.save(push_to_jira=push_to_jira)

    def get_queryset(self):
        return get_authorized_tests(Permissions.Import_Scan_Result)


# Authorization: authenticated users, DjangoModelPermissions
class EndpointMetaImporterView(mixins.CreateModelMixin,
                     viewsets.GenericViewSet):
    """
    Imports a CSV file into a product to propogate arbitrary meta and tags on endpoints.

    By Names:
    - Provide `product_name` of existing product

    By ID:
    - Provide the id of the product in the `product` parameter

    In this scenario Defect Dojo will look up the product by the provided details.
    """
    serializer_class = serializers.EndpointMetaImporterSerializer
    parser_classes = [MultiPartParser]
    queryset = Product.objects.all()
    permission_classes = (IsAuthenticated, permissions.UserHasMetaImportPermission)

    def perform_create(self, serializer):
        serializer.save()

    def get_queryset(self):
        return get_authorized_products(Permissions.Endpoint_Edit)


# Authorization: configuration
class LanguageTypeViewSet(mixins.ListModelMixin,
                          mixins.RetrieveModelMixin,
                          mixins.CreateModelMixin,
                          mixins.DestroyModelMixin,
                          mixins.UpdateModelMixin,
                          viewsets.GenericViewSet,
                          dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.LanguageTypeSerializer
    queryset = Language_Type.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'language', 'color')
    permission_classes = (permissions.UserHasConfigurationPermissionStaff, )


# Authorization: object-based
@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class LanguageViewSet(prefetch.PrefetchListMixin,
                      prefetch.PrefetchRetrieveMixin,
                      mixins.ListModelMixin,
                      mixins.RetrieveModelMixin,
                      mixins.DestroyModelMixin,
                      mixins.UpdateModelMixin,
                      mixins.CreateModelMixin,
                      viewsets.GenericViewSet,
                      dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.LanguageSerializer
    queryset = Languages.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'language', 'product')
    swagger_schema = prefetch.get_prefetch_schema(["languages_list", "languages_read"],
        serializers.LanguageSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasLanguagePermission)

    def get_queryset(self):
        return get_authorized_languages(Permissions.Language_View).distinct()


# Authorization: object-based
class ImportLanguagesView(mixins.CreateModelMixin,
                          viewsets.GenericViewSet):
    serializer_class = serializers.ImportLanguagesSerializer
    parser_classes = [MultiPartParser]
    queryset = Product.objects.none()
    permission_classes = (IsAuthenticated, permissions.UserHasLanguagePermission)

    def get_queryset(self):
        return get_authorized_products(Permissions.Language_Add)


# Authorization: object-based
class ReImportScanView(mixins.CreateModelMixin,
                       viewsets.GenericViewSet):
    """
    Reimports a scan report into an existing test.

    By ID:
    - Create a Product (or use an existing product)
    - Create an Engagement inside the product
    - Import a scan report and find the id of the Test
    - Provide this in the `test` parameter

    By Names:
    - Create a Product (or use an existing product)
    - Create an Engagement inside the product
    - Import a report which will create a Test
    - Provide `product_name`
    - Provide `engagement_name`
    - Optional: Provide `test_title`

    In this scenario Defect Dojo will look up the Test by the provided details.
    If no `test_title` is provided, the latest test inside the engagement will be chosen based on scan_type.

    When using names you can let the importer automatically create Engagements, Products and Product_Types
    by using `auto_create_context=True`.

    When `auto_create_context` is set to `True` you can use `deduplication_on_engagement` to restrict deduplication for
    imported Findings to the newly created Engagement.
    """
    serializer_class = serializers.ReImportScanSerializer
    parser_classes = [MultiPartParser]
    queryset = Test.objects.none()
    permission_classes = (IsAuthenticated, permissions.UserHasReimportPermission)

    def get_queryset(self):
        return get_authorized_tests(Permissions.Import_Scan_Result)

    def perform_create(self, serializer):
        test_id, test_title, scan_type, _, engagement_name, product_name, product_type_name, auto_create_context, deduplication_on_engagement, do_not_reactivate = serializers.get_import_meta_data_from_dict(serializer.validated_data)
        product = get_target_product_if_exists(product_name)
        engagement = get_target_engagement_if_exists(None, engagement_name, product)
        test = get_target_test_if_exists(test_id, test_title, scan_type, engagement)

        # when using auto_create_context, the engagement or product may not have been created yet
        jira_driver = test if test else engagement if engagement else product if product else None
        jira_project = jira_helper.get_jira_project(jira_driver) if jira_driver else None

        push_to_jira = serializer.validated_data.get('push_to_jira')
        if get_system_setting('enable_jira') and jira_project:
            push_to_jira = push_to_jira or jira_project.push_all_issues

        logger.debug('push_to_jira: %s', serializer.validated_data.get('push_to_jira'))
        serializer.save(push_to_jira=push_to_jira)


# Authorization: configuration
class NoteTypeViewSet(mixins.ListModelMixin,
                       mixins.RetrieveModelMixin,
                       mixins.DestroyModelMixin,
                       mixins.CreateModelMixin,
                       mixins.UpdateModelMixin,
                       viewsets.GenericViewSet,
                       dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.NoteTypeSerializer
    queryset = Note_Type.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'name', 'description', 'is_single', 'is_active', 'is_mandatory')
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser, )


# Authorization: superuser
class NotesViewSet(mixins.ListModelMixin,
                   mixins.RetrieveModelMixin,
                   mixins.UpdateModelMixin,
                   viewsets.GenericViewSet):
    serializer_class = serializers.NoteSerializer
    queryset = Notes.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'entry', 'author',
                    'private', 'date', 'edited',
                    'edit_time', 'editor')
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)


def report_generate(request, obj, options):
    user = Dojo_User.objects.get(id=request.user.id)
    product_type = None
    product = None
    engagement = None
    test = None
    endpoint = None
    endpoints = None
    endpoint_all_findings = None
    endpoint_monthly_counts = None
    endpoint_active_findings = None
    accepted_findings = None
    open_findings = None
    closed_findings = None
    verified_findings = None
    report_title = None
    report_subtitle = None

    include_finding_notes = False
    include_finding_images = False
    include_executive_summary = False
    include_table_of_contents = False

    report_info = "Generated By %s on %s" % (
        user.get_full_name(), (timezone.now().strftime("%m/%d/%Y %I:%M%p %Z")))

    # generate = "_generate" in request.GET
    report_name = str(obj)
    report_type = type(obj).__name__

    include_finding_notes = options.get('include_finding_notes', False)
    include_finding_images = options.get('include_finding_images', False)
    include_executive_summary = options.get('include_executive_summary', False)
    include_table_of_contents = options.get('include_table_of_contents', False)

    if type(obj).__name__ == "Product_Type":
        product_type = obj

        report_name = "Product Type Report: " + str(product_type)
        report_title = "Product Type Report"
        report_subtitle = str(product_type)

        findings = ReportFindingFilter(request.GET, prod_type=product_type, queryset=prefetch_related_findings_for_report(Finding.objects.filter(
            test__engagement__product__prod_type=product_type)))
        products = Product.objects.filter(prod_type=product_type,
                                          engagement__test__finding__in=findings.qs).distinct()
        engagements = Engagement.objects.filter(product__prod_type=product_type,
                                                test__finding__in=findings.qs).distinct()
        tests = Test.objects.filter(engagement__product__prod_type=product_type,
                                    finding__in=findings.qs).distinct()
        if len(findings.qs) > 0:
            start_date = timezone.make_aware(datetime.combine(findings.qs.last().date, datetime.min.time()))
        else:
            start_date = timezone.now()

        end_date = timezone.now()

        r = relativedelta(end_date, start_date)
        months_between = (r.years * 12) + r.months
        # include current month
        months_between += 1

        endpoint_monthly_counts = get_period_counts_legacy(findings.qs.order_by('numerical_severity'), findings.qs.order_by('numerical_severity'), None,
                                                            months_between, start_date,
                                                            relative_delta='months')

    elif type(obj).__name__ == "Product":
        product = obj

        report_name = "Product Report: " + str(product)
        report_title = "Product Report"
        report_subtitle = str(product)
        findings = ReportFindingFilter(request.GET, product=product, queryset=prefetch_related_findings_for_report(Finding.objects.filter(
            test__engagement__product=product)))
        ids = set(finding.id for finding in findings.qs)
        engagements = Engagement.objects.filter(test__finding__id__in=ids).distinct()
        tests = Test.objects.filter(finding__id__in=ids).distinct()
        ids = get_endpoint_ids(Endpoint.objects.filter(product=product).distinct())
        endpoints = Endpoint.objects.filter(id__in=ids)

    elif type(obj).__name__ == "Engagement":
        engagement = obj
        findings = ReportFindingFilter(request.GET, engagement=engagement,
                                       queryset=prefetch_related_findings_for_report(Finding.objects.filter(test__engagement=engagement)))
        report_name = "Engagement Report: " + str(engagement)

        report_title = "Engagement Report"
        report_subtitle = str(engagement)

        ids = set(finding.id for finding in findings.qs)
        tests = Test.objects.filter(finding__id__in=ids).distinct()
        ids = get_endpoint_ids(Endpoint.objects.filter(product=engagement.product).distinct())
        endpoints = Endpoint.objects.filter(id__in=ids)

    elif type(obj).__name__ == "Test":
        test = obj
        findings = ReportFindingFilter(request.GET, engagement=test.engagement,
                                       queryset=prefetch_related_findings_for_report(Finding.objects.filter(test=test)))
        filename = "test_finding_report.pdf"
        template = "dojo/test_pdf_report.html"
        report_name = "Test Report: " + str(test)
        report_title = "Test Report"
        report_subtitle = str(test)

    elif type(obj).__name__ == "Endpoint":
        endpoint = obj
        host = endpoint.host
        report_name = "Endpoint Report: " + host
        report_type = "Endpoint"
        endpoints = Endpoint.objects.filter(host=host,
                                            product=endpoint.product).distinct()
        report_title = "Endpoint Report"
        report_subtitle = host
        findings = ReportFindingFilter(request.GET,
                                       queryset=prefetch_related_findings_for_report(Finding.objects.filter(endpoints__in=endpoints)))

    elif type(obj).__name__ == "CastTaggedQuerySet":
        findings = ReportFindingFilter(request.GET,
                                             queryset=prefetch_related_findings_for_report(obj).distinct())

        report_name = 'Finding'
        report_type = 'Finding'
        report_title = "Finding Report"
        report_subtitle = ''

    else:
        raise Http404()

    result = {
        'product_type': product_type,
        'product': product,
        'engagement': engagement,
        'report_name': report_name,
        'report_info': report_info,
        'test': test,
        'endpoint': endpoint,
        'endpoints': endpoints,
        'findings': findings.qs.order_by('numerical_severity'),
        'include_table_of_contents': include_table_of_contents,
        'user': user,
        'team_name': settings.TEAM_NAME,
        'title': 'Generate Report',
        'user_id': request.user.id,
        'host': report_url_resolver(request),
    }

    finding_notes = []
    finding_files = []

    if include_finding_images:
        for finding in findings.qs.order_by('numerical_severity'):
            files = finding.files.all()
            if files:
                finding_files.append(
                    {
                        "finding_id": finding,
                        "files": files
                    }
                )
        result['finding_files'] = finding_files

    if include_finding_notes:
        for finding in findings.qs.order_by('numerical_severity'):
            notes = finding.notes.filter(private=False)
            if notes:
                finding_notes.append(
                    {
                        "finding_id": finding,
                        "notes": notes
                    }
                )
        result['finding_notes'] = finding_notes

    # Generating Executive summary based on obj type
    if include_executive_summary and type(obj).__name__ != "Endpoint":
        executive_summary = {}

        # Declare all required fields for executive summary
        engagement_name = None
        engagement_target_start = None
        engagement_target_end = None
        test_type_name = None
        test_target_start = None
        test_target_end = None
        test_environment_name = "unknown"  # a default of "unknown"
        test_strategy_ref = None
        total_findings = 0

        if type(obj).__name__ == "Product_Type":
            for prod_typ in obj.prod_type.all():
                engmnts = prod_typ.engagement_set.all()
                if engmnts:
                    for eng in engmnts:
                        if eng.name:
                            engagement_name = eng.name
                        engagement_target_start = eng.target_start
                        if eng.target_end:
                            engagement_target_end = eng.target_end
                        else:
                            engagement_target_end = "ongoing"
                        if eng.test_set.all():
                            for t in eng.test_set.all():
                                test_type_name = t.test_type.name
                                if t.environment:
                                    test_environment_name = t.environment.name
                                test_target_start = t.target_start
                                if t.target_end:
                                    test_target_end = t.target_end
                                else:
                                    test_target_end = "ongoing"
                            if eng.test_strategy:
                                test_strategy_ref = eng.test_strategy
                            else:
                                test_strategy_ref = ""
                total_findings = len(findings.qs.all())

        elif type(obj).__name__ == "Product":
            engs = obj.engagement_set.all()
            if engs:
                for eng in engs:
                    if eng.name:
                        engagement_name = eng.name
                    engagement_target_start = eng.target_start
                    if eng.target_end:
                        engagement_target_end = eng.target_end
                    else:
                        engagement_target_end = "ongoing"

                    if eng.test_set.all():
                        for t in eng.test_set.all():
                            test_type_name = t.test_type.name
                            if t.environment:
                                test_environment_name = t.environment.name
                    if eng.test_strategy:
                        test_strategy_ref = eng.test_strategy
                    else:
                        test_strategy_ref = ""
                total_findings = len(findings.qs.all())

        elif type(obj).__name__ == "Engagement":
            eng = obj
            if eng.name:
                engagement_name = eng.name
            engagement_target_start = eng.target_start
            if eng.target_end:
                engagement_target_end = eng.target_end
            else:
                engagement_target_end = "ongoing"

            if eng.test_set.all():
                for t in eng.test_set.all():
                    test_type_name = t.test_type.name
                    if t.environment:
                        test_environment_name = t.environment.name
            if eng.test_strategy:
                test_strategy_ref = eng.test_strategy
            else:
                test_strategy_ref = ""
            total_findings = len(findings.qs.all())

        elif type(obj).__name__ == "Test":
            t = obj
            test_type_name = t.test_type.name
            test_target_start = t.target_start
            if t.target_end:
                test_target_end = t.target_end
            else:
                test_target_end = "ongoing"
            total_findings = len(findings.qs.all())
            if t.engagement.name:
                engagement_name = t.engagement.name
            engagement_target_start = t.engagement.target_start
            if t.engagement.target_end:
                engagement_target_end = t.engagement.target_end
            else:
                engagement_target_end = "ongoing"
        else:
            pass  # do nothing

        executive_summary = {
            'engagement_name': engagement_name,
            'engagement_target_start': engagement_target_start,
            'engagement_target_end': engagement_target_end,
            'test_type_name': test_type_name,
            'test_target_start': test_target_start,
            'test_target_end': test_target_end,
            'test_environment_name': test_environment_name,
            'test_strategy_ref': test_strategy_ref,
            'total_findings': total_findings
        }
        # End of executive summary generation

        result['executive_summary'] = executive_summary

    return result


# Authorization: superuser
class SystemSettingsViewSet(mixins.ListModelMixin,
                    mixins.UpdateModelMixin,
                    viewsets.GenericViewSet):
    """ Basic control over System Settings. Use 'id' 1 for PUT, PATCH operations """
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)
    serializer_class = serializers.SystemSettingsSerializer
    queryset = System_Settings.objects.all()


# Authorization: superuser
@extend_schema_view(
    list=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    ),
    retrieve=extend_schema(parameters=[
            OpenApiParameter("prefetch", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                                description="List of fields for which to prefetch model instances and add those to the response"),
    ],
    )
)
class NotificationsViewSet(prefetch.PrefetchListMixin,
                           prefetch.PrefetchRetrieveMixin,
                           mixins.ListModelMixin,
                           mixins.RetrieveModelMixin,
                           mixins.DestroyModelMixin,
                           mixins.CreateModelMixin,
                           mixins.UpdateModelMixin,
                           viewsets.GenericViewSet,
                           dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.NotificationsSerializer
    queryset = Notifications.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'user', 'product', 'template')
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)
    swagger_schema = prefetch.get_prefetch_schema(["notifications_list", "notifications_read"],
        serializers.NotificationsSerializer).to_schema()


class EngagementPresetsViewset(prefetch.PrefetchListMixin,
                               prefetch.PrefetchRetrieveMixin,
                               mixins.ListModelMixin,
                               mixins.RetrieveModelMixin,
                               mixins.UpdateModelMixin,
                               mixins.DestroyModelMixin,
                               mixins.CreateModelMixin,
                               viewsets.GenericViewSet,
                               dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.EngagementPresetsSerializer
    queryset = Engagement_Presets.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'title', 'product')
    swagger_schema = prefetch.get_prefetch_schema(["engagement_presets_list", "engagement_presets_read"], serializers.EngagementPresetsSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasEngagementPresetPermission)

    def get_queryset(self):
        return get_authorized_engagement_presets(Permissions.Product_View)


class EngagementCheckListViewset(prefetch.PrefetchListMixin,
                               prefetch.PrefetchRetrieveMixin,
                               mixins.ListModelMixin,
                               mixins.RetrieveModelMixin,
                               mixins.UpdateModelMixin,
                               mixins.DestroyModelMixin,
                               mixins.CreateModelMixin,
                               viewsets.GenericViewSet,
                               dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.EngagementCheckListSerializer
    queryset = Check_List.objects.none()
    filter_backends = (DjangoFilterBackend,)
    swagger_schema = prefetch.get_prefetch_schema(["engagement_checklists_list", "engagement_checklists_read"], serializers.EngagementCheckListSerializer).to_schema()
    permission_classes = (IsAuthenticated, permissions.UserHasEngagementPermission)

    def get_queryset(self):
        return get_authorized_engagement_checklists(Permissions.Product_View)


class NetworkLocationsViewset(mixins.ListModelMixin,
                              mixins.RetrieveModelMixin,
                              mixins.UpdateModelMixin,
                              mixins.DestroyModelMixin,
                              mixins.CreateModelMixin,
                              viewsets.GenericViewSet,
                              dojo_mixins.DeletePreviewModelMixin):
    serializer_class = serializers.NetworkLocationsSerializer
    queryset = Network_Locations.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'location')
    permission_classes = (IsAuthenticated, DjangoModelPermissions)


# Authorization: superuser
class ConfigurationPermissionViewSet(mixins.RetrieveModelMixin,
                                     mixins.ListModelMixin,
                                     viewsets.GenericViewSet):
    serializer_class = serializers.ConfigurationPermissionSerializer
    queryset = Permission.objects.filter(codename__in=get_configuration_permissions_codenames())
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('id', 'name', 'codename')
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)


class SLAConfigurationViewset(mixins.ListModelMixin,
                              mixins.RetrieveModelMixin,
                              mixins.UpdateModelMixin,
                              mixins.DestroyModelMixin,
                              mixins.CreateModelMixin,
                              viewsets.GenericViewSet):
    serializer_class = serializers.SLAConfigurationSerializer
    queryset = SLA_Configuration.objects.all()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, DjangoModelPermissions)


class QuestionnaireQuestionViewSet(mixins.ListModelMixin,
                                   mixins.RetrieveModelMixin,
                                   viewsets.GenericViewSet,
                                   dojo_mixins.QuestionSubClassFieldsMixin):
    serializer_class = serializers.QuestionnaireQuestionSerializer
    queryset = Question.objects.all()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (permissions.UserHasEngagementPermission, DjangoModelPermissions)


class QuestionnaireAnswerViewSet(mixins.ListModelMixin,
                                 mixins.RetrieveModelMixin,
                                 viewsets.GenericViewSet,
                                 dojo_mixins.AnswerSubClassFieldsMixin):
    serializer_class = serializers.QuestionnaireAnswerSerializer
    queryset = Answer.objects.all()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (permissions.UserHasEngagementPermission, DjangoModelPermissions)


class QuestionnaireGeneralSurveyViewSet(mixins.ListModelMixin,
                                        mixins.RetrieveModelMixin,
                                        viewsets.GenericViewSet):
    serializer_class = serializers.QuestionnaireGeneralSurveySerializer
    queryset = General_Survey.objects.all()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (permissions.UserHasEngagementPermission, DjangoModelPermissions)


class QuestionnaireEngagementSurveyViewSet(mixins.ListModelMixin,
                                           mixins.RetrieveModelMixin,
                                           viewsets.GenericViewSet):
    serializer_class = serializers.QuestionnaireEngagementSurveySerializer
    queryset = Engagement_Survey.objects.all()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (permissions.UserHasEngagementPermission, DjangoModelPermissions)


class QuestionnaireAnsweredSurveyViewSet(prefetch.PrefetchListMixin,
                                         prefetch.PrefetchRetrieveMixin,
                                         mixins.ListModelMixin,
                                         mixins.RetrieveModelMixin,
                                         viewsets.GenericViewSet):
    serializer_class = serializers.QuestionnaireAnsweredSurveySerializer
    queryset = Answered_Survey.objects.all()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (permissions.UserHasEngagementPermission, DjangoModelPermissions)
    swagger_schema = prefetch.get_prefetch_schema(["questionnaire_answered_questionnaires_list", "questionnaire_answered_questionnaires_read"], serializers.QuestionnaireAnsweredSurveySerializer).to_schema()
