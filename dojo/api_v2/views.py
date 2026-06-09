import logging
from datetime import datetime

import pghistory
from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.db.models.query import QuerySet as DjangoQuerySet
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.renderers import OpenApiJsonRenderer2
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    extend_schema,
    extend_schema_view,
)
from drf_spectacular.views import SpectacularAPIView
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import DjangoModelPermissions, IsAuthenticated
from rest_framework.response import Response

from dojo.api_v2 import (
    mixins as dojo_mixins,
)
from dojo.api_v2 import (
    prefetch,
    serializers,
)
from dojo.authorization import api_permissions as permissions
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.endpoint.ui.views import get_endpoint_ids
from dojo.filters import (
    ApiAppAnalysisFilter,
    ApiDojoMetaFilter,
)
from dojo.finding.ui.filters import (
    ReportFindingFilter,
    ReportFindingFilterWithoutObjectLookups,
)
from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.jira import services as jira_services
from dojo.labels import get_labels
from dojo.models import (
    App_Analysis,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Finding,
    Language_Type,
    Languages,
    Network_Locations,
    Product,
    SLA_Configuration,
    Sonarqube_Issue,
    Sonarqube_Issue_Transition,
    System_Settings,
    Test,
)
from dojo.product.queries import (
    get_authorized_app_analysis,
    get_authorized_dojo_meta,
    get_authorized_languages,
    get_authorized_products,
)
from dojo.reports.ui.views import (
    prefetch_related_findings_for_report,
    report_url_resolver,
)
from dojo.test.queries import get_authorized_tests
from dojo.user.utils import get_configuration_permissions_codenames
from dojo.utils import (
    get_celery_queue_details,
    get_celery_queue_length,
    get_celery_worker_status,
    get_system_setting,
    purge_celery_queue,
    purge_celery_queue_by_task_name,
)

logger = logging.getLogger(__name__)


labels = get_labels()


def schema_with_prefetch() -> dict:
    return {
        "list": extend_schema(
            parameters=[
                OpenApiParameter(
                    "prefetch",
                    OpenApiTypes.STR,
                    OpenApiParameter.QUERY,
                    required=False,
                    description="List of fields for which to prefetch model instances and add those to the response",
                ),
            ],
        ),
        "retrieve": extend_schema(
            parameters=[
                OpenApiParameter(
                    "prefetch",
                    OpenApiTypes.STR,
                    OpenApiParameter.QUERY,
                    required=False,
                    description="List of fields for which to prefetch model instances and add those to the response",
                ),
            ],
        ),
    }


class DojoOpenApiJsonRenderer(OpenApiJsonRenderer2):
    def get_indent(self, accepted_media_type, renderer_context):
        if accepted_media_type and "indent" in accepted_media_type:
            return super().get_indent(accepted_media_type, renderer_context)
        return renderer_context.get("indent", None)


class DojoSpectacularAPIView(SpectacularAPIView):
    renderer_classes = [DojoOpenApiJsonRenderer, *SpectacularAPIView.renderer_classes]


class DojoModelViewSet(
    viewsets.ModelViewSet,
    dojo_mixins.DeletePreviewModelMixin,
):
    pass


class PrefetchDojoModelViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    DojoModelViewSet,
):
    pass


class DeprecationNoticeMixin:

    deprecated: bool | None = None
    end_of_life_date: datetime | None = None

    def finalize_response(self, request, response, *args, **kwargs):
        if self.deprecated is not None:
            response["X-Deprecated"] = self.deprecated
        if self.end_of_life_date is not None:
            response["X-End-Of-Life-Date"] = self.end_of_life_date.isoformat()
        return super().finalize_response(request, response, *args, **kwargs)


# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
# These are technologies in the UI and the API!
# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class AppAnalysisViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.AppAnalysisSerializer
    queryset = App_Analysis.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiAppAnalysisFilter

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasAppAnalysisPermission,
    )

    def get_queryset(self):
        return get_authorized_app_analysis("view")


# Authorization: configuration
from dojo.jira.api.views import (  # noqa: E402, F401 backward compat
    JiraInstanceViewSet,
    JiraIssuesViewSet,
    JiraProjectViewSet,
)


# Authorization: superuser
class SonarqubeIssueViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.SonarqubeIssueSerializer
    queryset = Sonarqube_Issue.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "key", "status", "type"]
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return Sonarqube_Issue.objects.all().order_by("id")


# Authorization: superuser
class SonarqubeIssueTransitionViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.SonarqubeIssueTransitionSerializer
    queryset = Sonarqube_Issue_Transition.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "sonarqube_issue",
        "finding_status",
        "sonarqube_status",
        "transitions",
    ]
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return Sonarqube_Issue_Transition.objects.all().order_by("id")


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class DojoMetaViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.MetaSerializer
    queryset = DojoMeta.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiDojoMetaFilter
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasDojoMetaPermission,
    )

    def get_queryset(self):
        return get_authorized_dojo_meta("view")

    @extend_schema(
        methods=["post", "patch"],
        request=serializers.MetaMainSerializer,
        responses={status.HTTP_200_OK: serializers.MetaMainSerializer},
        filters=False,
    )
    @action(
        detail=False, methods=["post", "patch"], pagination_class=None,
    )
    def batch(self, request, pk=None):
        serialized_data = serializers.MetaMainSerializer(data=request.data)
        if serialized_data.is_valid(raise_exception=True):
            if request.method == "POST":
                self.process_post(request)
                status_code = status.HTTP_201_CREATED
            if request.method == "PATCH":
                self.process_patch(request)
                status_code = status.HTTP_200_OK

        return Response(status=status_code, data=serialized_data.data)

    def _fetch_and_authorize_parents(self, request, permission_map):
        """Fetch parent objects and verify the user has the required permissions."""
        data = request.data
        parents = {}
        for field, (model, permission) in permission_map.items():
            obj = model.objects.filter(id=data.get(field)).first()
            if obj:
                user_has_permission_or_403(request.user, obj, permission)
            parents[field] = obj
        return parents

    def process_post(self, request):
        data = request.data
        parents = self._fetch_and_authorize_parents(request, {
            "product": (Product, "edit"),
            "finding": (Finding, "edit"),
            "endpoint": (Endpoint, "edit"),
        })
        metalist = data.get("metadata")
        for metadata in metalist:
            try:
                DojoMeta.objects.create(
                    product=parents["product"],
                    finding=parents["finding"],
                    endpoint=parents["endpoint"],
                    name=metadata.get("name"),
                    value=metadata.get("value"),
                    )
            except (IntegrityError) as ex:  # this should not happen as the data was validated in the batch call
                raise ValidationError(str(ex))

    def process_patch(self, request):
        data = request.data
        parents = self._fetch_and_authorize_parents(request, {
            "product": (Product, "edit"),
            "finding": (Finding, "edit"),
            "endpoint": (Endpoint, "edit"),
        })
        metalist = data.get("metadata")
        for metadata in metalist:
            dojometa = DojoMeta.objects.filter(product=parents["product"], finding=parents["finding"], endpoint=parents["endpoint"], name=metadata.get("name"))
            if dojometa:
                try:
                    dojometa.update(
                        name=metadata.get("name"),
                        value=metadata.get("value"),
                        )
                except (IntegrityError) as ex:
                    raise ValidationError(str(ex))
            else:
                msg = f"Metadata {metadata.get('name')} not found for object."
                raise ValidationError(msg)


# DevelopmentEnvironmentViewSet moved to dojo/development_environment/api/views.py
# RegulationsViewSet moved to dojo/regulations/api/views.py


# Authorization: authenticated users, DjangoModelPermissions
class ImportScanView(mixins.CreateModelMixin, viewsets.GenericViewSet):

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
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            converted_dict = auto_create.convert_querydict_to_dict(serializer.validated_data)
            auto_create.process_import_meta_data_from_dict(converted_dict)
            # Get an existing product
            product = auto_create.get_target_product_if_exists(**converted_dict)
            engagement = auto_create.get_target_engagement_if_exists(product=product, **converted_dict)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(str(e))

        # when using auto_create_context, the engagement or product may not
        # have been created yet
        push_to_jira = serializer.validated_data.get("push_to_jira")
        if get_system_setting("enable_jira"):
            jira_driver = engagement or (product or None)
            if jira_project := (jira_services.get_project(jira_driver) if jira_driver else None):
                push_to_jira = push_to_jira or jira_project.push_all_issues

        # Add pghistory context for audit trail (adds to existing middleware context).
        # /api/vue is the Pro UI
        source = "import_vue" if "/api/vue/" in self.request.path else "import_api"
        pghistory.context(
            source=source,
            scan_type=serializer.validated_data.get("scan_type"),
        )
        serializer.save(push_to_jira=push_to_jira)
        # Add test_id to pghistory context now that test is created
        if test_id := serializer.data.get("test"):
            pghistory.context(test_id=test_id)

    def get_queryset(self):
        return get_authorized_tests("import")


# Authorization: configuration
class LanguageTypeViewSet(
    DojoModelViewSet,
):
    serializer_class = serializers.LanguageTypeSerializer
    queryset = Language_Type.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "language", "color"]
    permission_classes = (permissions.UserHasConfigurationPermissionStaff,)

    def get_queryset(self):
        return Language_Type.objects.all().order_by("id")


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class LanguageViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.LanguageSerializer
    queryset = Languages.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "language", "product"]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasLanguagePermission,
    )

    def get_queryset(self):
        return get_authorized_languages("view").distinct()


# Authorization: object-based
class ImportLanguagesView(mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = serializers.ImportLanguagesSerializer
    parser_classes = [MultiPartParser]
    queryset = Product.objects.none()
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasLanguagePermission,
    )

    def get_queryset(self):
        return get_authorized_products("add")


# Authorization: object-based
class ReImportScanView(mixins.CreateModelMixin, viewsets.GenericViewSet):

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
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasReimportPermission,
    )

    def get_queryset(self):
        return get_authorized_tests("import")

    def perform_create(self, serializer):
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            converted_dict = auto_create.convert_querydict_to_dict(serializer.validated_data)
            auto_create.process_import_meta_data_from_dict(converted_dict)
            # Get an existing product
            product = auto_create.get_target_product_if_exists(**converted_dict)
            engagement = auto_create.get_target_engagement_if_exists(product=product, **converted_dict)
            test = auto_create.get_target_test_if_exists(engagement=engagement, **converted_dict)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(str(e))

        # when using auto_create_context, the engagement or product may not
        # have been created yet
        push_to_jira = serializer.validated_data.get("push_to_jira")
        if get_system_setting("enable_jira"):
            jira_driver = test or (engagement or (product or None))
            if jira_project := (jira_services.get_project(jira_driver) if jira_driver else None):
                push_to_jira = push_to_jira or jira_project.push_all_issues
        logger.debug("push_to_jira: %s", push_to_jira)
        # Add pghistory context for audit trail (adds to existing middleware context)
        # For reimport, test may already exist or be created during save
        test_id = test.id if test else serializer.validated_data.get("test", {})
        if hasattr(test_id, "id"):
            test_id = test_id.id
        # /api/vue is the Pro UI
        source = "reimport_vue" if "/api/vue/" in self.request.path else "reimport_api"
        pghistory.context(
            source=source,
            test_id=test_id if isinstance(test_id, int) else None,
            scan_type=serializer.validated_data.get("scan_type"),
        )
        serializer.save(push_to_jira=push_to_jira)
        # Update test_id if it wasn't available before save
        if test_id_from_response := serializer.data.get("test"):
            pghistory.context(test_id=test_id_from_response)


from dojo.note_type.api.views import NoteTypeViewSet  # noqa: E402, F401 -- re-export; urls.py imports by name
from dojo.notes.api.views import NotesViewSet  # noqa: E402, F401 -- re-export; urls.py imports by name


def report_generate(request, obj, options):
    user = Dojo_User.objects.get(id=request.user.id)
    product_type = None
    product = None
    engagement = None
    test = None
    endpoint = None
    endpoints = None

    include_finding_notes = False
    include_finding_images = False
    include_executive_summary = False
    include_table_of_contents = False

    report_info = "Generated By {} on {}".format(
        user.get_full_name(),
        (timezone.now().strftime("%m/%d/%Y %I:%M%p %Z")),
    )

    # generate = "_generate" in request.GET
    report_name = str(obj)

    include_finding_notes = options.get("include_finding_notes", False)
    include_finding_images = options.get("include_finding_images", False)
    include_executive_summary = options.get("include_executive_summary", False)
    include_table_of_contents = options.get("include_table_of_contents", False)
    filter_string_matching = get_system_setting("filter_string_matching", False)
    report_finding_filter_class = ReportFindingFilterWithoutObjectLookups if filter_string_matching else ReportFindingFilter

    if type(obj).__name__ == "Product_Type":
        product_type = obj

        report_name = labels.ORG_REPORT_WITH_NAME_TITLE % {"name": str(product_type)}

        findings = report_finding_filter_class(
            request.GET,
            prod_type=product_type,
            queryset=prefetch_related_findings_for_report(
                Finding.objects.filter(
                    test__engagement__product__prod_type=product_type,
                ),
            ),
        )

        if len(findings.qs) > 0:
            start_date = timezone.make_aware(
                datetime.combine(findings.qs.last().date, datetime.min.time()),
            )
        else:
            start_date = timezone.now()

        end_date = timezone.now()

        r = relativedelta(end_date, start_date)
        months_between = (r.years * 12) + r.months
        # include current month
        months_between += 1

    elif type(obj).__name__ == "Product":
        product = obj

        report_name = labels.ASSET_REPORT_WITH_NAME_TITLE % {"name": str(product)}

        findings = report_finding_filter_class(
            request.GET,
            product=product,
            queryset=prefetch_related_findings_for_report(
                Finding.objects.filter(test__engagement__product=product),
            ),
        )
        ids = get_endpoint_ids(
            Endpoint.objects.filter(product=product).distinct(),
        )
        endpoints = Endpoint.objects.filter(id__in=ids)

    elif type(obj).__name__ == "Engagement":
        engagement = obj
        findings = report_finding_filter_class(
            request.GET,
            engagement=engagement,
            queryset=prefetch_related_findings_for_report(
                Finding.objects.filter(test__engagement=engagement),
            ),
        )
        report_name = "Engagement Report: " + str(engagement)

        ids = set(finding.id for finding in findings.qs)  # noqa: C401
        ids = get_endpoint_ids(
            Endpoint.objects.filter(product=engagement.product).distinct(),
        )
        endpoints = Endpoint.objects.filter(id__in=ids)

    elif type(obj).__name__ == "Test":
        test = obj
        findings = report_finding_filter_class(
            request.GET,
            engagement=test.engagement,
            queryset=prefetch_related_findings_for_report(
                Finding.objects.filter(test=test),
            ),
        )
        report_name = "Test Report: " + str(test)

    elif type(obj).__name__ == "Endpoint":
        endpoint = obj
        host = endpoint.host
        report_name = "Endpoint Report: " + host
        endpoints = Endpoint.objects.filter(
            host=host, product=endpoint.product,
        ).distinct()
        findings = report_finding_filter_class(
            request.GET,
            queryset=prefetch_related_findings_for_report(
                Finding.objects.filter(endpoints__in=endpoints),
            ),
        )

    elif isinstance(obj, DjangoQuerySet):
        # Support any Django QuerySet (including Tagulous CastTaggedQuerySet)
        findings = report_finding_filter_class(
            request.GET,
            queryset=prefetch_related_findings_for_report(obj).distinct(),
        )

        report_name = "Finding"
    else:
        obj_type = type(obj).__name__
        msg = f"Report cannot be generated for object of type {obj_type}"
        logger.warning(msg)
        raise ValidationError(msg)

    result = {
        "product_type": product_type,
        "product": product,
        "engagement": engagement,
        "report_name": report_name,
        "report_info": report_info,
        "test": test,
        "endpoint": endpoint,
        "endpoints": endpoints,
        "findings": findings.qs.order_by("numerical_severity"),
        "include_table_of_contents": include_table_of_contents,
        "user": user,
        "team_name": settings.TEAM_NAME,
        "title": "Generate Report",
        "user_id": request.user.id,
        "host": report_url_resolver(request),
    }

    finding_notes = []
    finding_files = []

    if include_finding_images:
        for finding in findings.qs.order_by("numerical_severity"):
            files = finding.files.all()
            if files:
                finding_files.append({"finding_id": finding, "files": files})
        result["finding_files"] = finding_files

    if include_finding_notes:
        for finding in findings.qs.order_by("numerical_severity"):
            notes = finding.notes.filter(private=False)
            if notes:
                finding_notes.append({"finding_id": finding, "notes": notes})
        result["finding_notes"] = finding_notes

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
                        engagement_target_end = eng.target_end or "ongoing"
                        if eng.test_set.all():
                            for t in eng.test_set.all():
                                test_type_name = t.test_type.name
                                if t.environment:
                                    test_environment_name = t.environment.name
                                test_target_start = t.target_start
                                test_target_end = t.target_end or "ongoing"
                            test_strategy_ref = eng.test_strategy or ""
                total_findings = len(findings.qs.all())

        elif type(obj).__name__ == "Product":
            engs = obj.engagement_set.all()
            if engs:
                for eng in engs:
                    if eng.name:
                        engagement_name = eng.name
                    engagement_target_start = eng.target_start
                    engagement_target_end = eng.target_end or "ongoing"

                    if eng.test_set.all():
                        for t in eng.test_set.all():
                            test_type_name = t.test_type.name
                            if t.environment:
                                test_environment_name = t.environment.name
                    test_strategy_ref = eng.test_strategy or ""
                total_findings = len(findings.qs.all())

        elif type(obj).__name__ == "Engagement":
            eng = obj
            if eng.name:
                engagement_name = eng.name
            engagement_target_start = eng.target_start
            engagement_target_end = eng.target_end or "ongoing"

            if eng.test_set.all():
                for t in eng.test_set.all():
                    test_type_name = t.test_type.name
                    if t.environment:
                        test_environment_name = t.environment.name
            test_strategy_ref = eng.test_strategy or ""
            total_findings = len(findings.qs.all())

        elif type(obj).__name__ == "Test":
            t = obj
            test_type_name = t.test_type.name
            test_target_start = t.target_start
            test_target_end = t.target_end or "ongoing"
            total_findings = len(findings.qs.all())
            if t.engagement.name:
                engagement_name = t.engagement.name
            engagement_target_start = t.engagement.target_start
            engagement_target_end = t.engagement.target_end or "ongoing"
        else:
            pass  # do nothing

        executive_summary = {
            "engagement_name": engagement_name,
            "engagement_target_start": engagement_target_start,
            "engagement_target_end": engagement_target_end,
            "test_type_name": test_type_name,
            "test_target_start": test_target_start,
            "test_target_end": test_target_end,
            "test_environment_name": test_environment_name,
            "test_strategy_ref": test_strategy_ref,
            "total_findings": total_findings,
        }
        # End of executive summary generation

        result["executive_summary"] = executive_summary

    return result


class CeleryViewSet(viewsets.ViewSet):
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)
    queryset = System_Settings.objects.none()

    @extend_schema(
        responses=serializers.CeleryStatusSerializer,
        summary="Get Celery worker and queue status",
        description=(
            "Returns Celery worker liveness, pending queue length, and the active task "
            "timeout/expiry configuration. Uses the Celery control channel (pidbox) for "
            "worker status so it works correctly even when the task queue is clogged."
        ),
    )
    @action(detail=False, methods=["get"], url_path="status")
    def status(self, request):
        queue_length = get_celery_queue_length()
        data = {
            "worker_status": get_celery_worker_status(),
            "broker_status": queue_length is not None,
            "queue_length": queue_length,
            "task_time_limit": getattr(settings, "CELERY_TASK_TIME_LIMIT", None),
            "task_soft_time_limit": getattr(settings, "CELERY_TASK_SOFT_TIME_LIMIT", None),
            "task_default_expires": getattr(settings, "CELERY_TASK_DEFAULT_EXPIRES", None),
        }
        return Response(serializers.CeleryStatusSerializer(data).data)

    @extend_schema(
        request=None,
        responses={200: {"type": "object", "properties": {"purged": {"type": "integer"}}}},
        summary="Purge all pending Celery tasks from the queue",
        description=(
            "Removes all pending tasks from the default Celery queue. Tasks already being "
            "executed by workers are not affected. Note: if deduplication tasks were queued, "
            "you may need to re-run deduplication manually via `python manage.py dedupe`."
        ),
    )
    @action(detail=False, methods=["post"], url_path="queue/purge")
    def queue_purge(self, request):
        purged = purge_celery_queue()
        return Response({"purged": purged})

    @extend_schema(
        responses=serializers.CeleryQueueTaskDetailSerializer(many=True),
        summary="Get per-task breakdown of the Celery queue",
        description=(
            "Scans every message in the queue (O(N)) and returns task name, count, and "
            "oldest/newest queue positions. May be slow for large queues."
        ),
    )
    @action(detail=False, methods=["get"], url_path="queue/details")
    def queue_details(self, request):
        details = get_celery_queue_details()
        if details is None:
            return Response({"error": "Unable to read queue details."}, status=503)
        return Response(serializers.CeleryQueueTaskDetailSerializer(details, many=True).data)

    @extend_schema(
        request={"application/json": {"type": "object", "properties": {"task_name": {"type": "string"}}, "required": ["task_name"]}},
        responses={200: {"type": "object", "properties": {"purged": {"type": "integer"}}}},
        summary="Purge all queued tasks with a given task name",
        description="Removes all pending tasks matching the given task name from the default Celery queue.",
    )
    @action(detail=False, methods=["post"], url_path="queue/task/purge")
    def queue_task_purge(self, request):
        task_name = request.data.get("task_name", "").strip()
        if not task_name:
            return Response({"error": "task_name is required."}, status=400)
        purged = purge_celery_queue_by_task_name(task_name)
        if purged is None:
            return Response({"error": "Unable to purge tasks."}, status=503)
        return Response({"purged": purged})


class NetworkLocationsViewset(
    DojoModelViewSet,
):
    serializer_class = serializers.NetworkLocationsSerializer
    queryset = Network_Locations.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "location"]
    permission_classes = (IsAuthenticated, DjangoModelPermissions)

    def get_queryset(self):
        return Network_Locations.objects.all().order_by("id")


# Authorization: superuser
class ConfigurationPermissionViewSet(
    viewsets.ReadOnlyModelViewSet,
):
    serializer_class = serializers.ConfigurationPermissionSerializer
    queryset = Permission.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "name", "codename"]
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return Permission.objects.filter(
            codename__in=get_configuration_permissions_codenames(),
        ).order_by("id")


class SLAConfigurationViewset(
    DojoModelViewSet,
):
    serializer_class = serializers.SLAConfigurationSerializer
    queryset = SLA_Configuration.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, permissions.UserHasSLAPermission)

    def get_queryset(self):
        return SLA_Configuration.objects.all().order_by("id")


# AnnouncementViewSet moved to dojo/announcement/api/views.py
