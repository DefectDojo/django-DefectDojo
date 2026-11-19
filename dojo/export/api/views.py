import heapq
import math
from collections import defaultdict
from collections.abc import Iterator
from itertools import batched, groupby
from operator import attrgetter, itemgetter

from auditlog.models import LogEntry
from django.conf import settings
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.contrib.postgres.aggregates import ArrayAgg
from django.db.models import Count, F, OuterRef, Prefetch, Q, QuerySet, Subquery
from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.authtoken.models import Token
from rest_framework.renderers import BaseRenderer, JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from dojo import __version__
from dojo.api_v2.serializers import SLAConfigurationSerializer
from dojo.authorization.api_permissions import IsSuperUser
from dojo.development_environment.api.serializer import DevelopmentEnvironmentSerializer
from dojo.endpoint.models import Endpoint_Status
from dojo.export.api.serializers import (
    CHECK_LIST_ISSUE_FIELDS,
    ExportAnnouncementSerializer,
    ExportAnsweredSurveySerializer,
    ExportAPIScanConfigurationSerializer,
    ExportAuditEventSerializer,
    ExportBenchmarkResultSerializer,
    ExportBenchmarkTypeSerializer,
    ExportContactSerializer,
    ExportEngagementPresetSerializer,
    ExportEngagementSerializer,
    ExportFindingSerializer,
    ExportGeneralSurveySerializer,
    ExportGithubConfigurationSerializer,
    ExportGithubProjectSerializer,
    ExportJiraInstanceSerializer,
    ExportJiraProjectSerializer,
    ExportLegacyAuditEntrySerializer,
    ExportLoginBannerSerializer,
    ExportParamsSerializer,
    ExportProductSerializer,
    ExportQuestionnaireSerializer,
    ExportReportTypeSerializer,
    ExportRiskAcceptanceSerializer,
    ExportTestImportSerializer,
    ExportTestSerializer,
    ExportTestTypeSerializer,
    ExportToolConfigurationSerializer,
    ExportTrackingFileSerializer,
    ExportUserSerializer,
    ManifestParamsSerializer,
    audit_event_model,
    configuration_permission_names,
    export_product_endpoint,
    file_size,
    prefetch_answers,
    prefetch_questions,
    readable_threat_model,
    render_datetime,
    threat_model_file,
)
from dojo.finding.api.serializer import FindingTemplateSerializer
from dojo.github.models import GITHUB_Conf, GITHUB_Issue, GITHUB_PKey
from dojo.location.feature import locations_enabled
from dojo.location.models import LocationProductReference
from dojo.models import (
    Answered_Survey,
    Benchmark_Category,
    Benchmark_Product,
    Benchmark_Product_Summary,
    Benchmark_Requirement,
    Benchmark_Type,
    BurpRawRequestResponse,
    Check_List,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Engagement,
    Engagement_Presets,
    Engagement_Survey,
    FileUpload,
    Finding,
    Finding_Group,
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
    Objects_Product,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Risk_Acceptance,
    Sonarqube_Issue_Transition,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
)
from dojo.note_type.api.serializer import NoteTypeSerializer
from dojo.notes.helper import notes_prefetch
from dojo.product_attributes.api.serializer import (
    ProductLifecycleSerializer,
    ProductOriginSerializer,
    ProductPlatformSerializer,
)
from dojo.regulations.api.serializer import RegulationSerializer
from dojo.tool_type.api.serializer import ToolTypeSerializer
from dojo.user.authentication import token_expires_at
from dojo.utils import get_system_setting
from dojo.vulnerability.queries import vulnerability_id_prefetch

EXPORT_CHUNK_SIZE = 500
ACTIONS_PER_LINE = 10000
DOCS_URL = "https://docs.defectdojo.com/automation/api/product_export/"
SCHEMA_VERSION = 1
COUNT_KEYS = (
    "engagements", "tests", "findings", "endpoints", "notes", "files", "files_over_cap", "risk_acceptances", "finding_groups",
)
IMPORT_HISTORY_COUNT_KEYS = ("test_imports", "test_import_actions")
AUDIT_HISTORY_COUNT_KEYS = ("audit_events", "legacy_audit_entries")
PRODUCT_EXTRAS_COUNT_KEYS = ("tracking_files", "benchmarks", "answered_surveys")
JIRA_COUNT_KEYS = ("jira_projects", "jira_issues")
EXTERNAL_ISSUES_COUNT_KEYS = ("github_projects", "github_issues", "sonarqube_issues")
HISTORY_FEATURES = ("import_history", "audit_history")
AUDIT_MODELS = (Product, Engagement, Test, Finding, Finding_Group, Risk_Acceptance)
# From an audited object to its product id. A risk acceptance has two paths: see risk_acceptance_in.
AUDIT_PRODUCT_PATHS = {
    Product: "id",
    Engagement: "product_id",
    Test: "engagement__product_id",
    Finding: "test__engagement__product_id",
    Finding_Group: "test__engagement__product_id",
}
REFERENCE_SERIALIZERS = {
    "sla_configurations": SLAConfigurationSerializer,
    "development_environments": DevelopmentEnvironmentSerializer,
    "regulations": RegulationSerializer,
    "test_types": ExportTestTypeSerializer,
    "note_types": NoteTypeSerializer,
    "product_platforms": ProductPlatformSerializer,
    "product_lifecycles": ProductLifecycleSerializer,
    "product_origins": ProductOriginSerializer,
    "finding_templates": FindingTemplateSerializer,
    "tool_types": ToolTypeSerializer,
    "tool_configurations": ExportToolConfigurationSerializer,
    "contacts": ExportContactSerializer,
    "report_types": ExportReportTypeSerializer,
    "general_surveys": ExportGeneralSurveySerializer,
}


class NDJSONRenderer(BaseRenderer):
    media_type = "application/x-ndjson"
    format = "ndjson"

    def render(self, data, accepted_media_type=None, renderer_context=None) -> bytes:
        try:
            line = JSONRenderer().render(data)
        except ValueError:
            line = JSONRenderer().render(finite(data))
        # DRF escapes U+2028 and U+2029 but not U+0085, and str.splitlines() splits on all three.
        return line.replace(b"\xc2\x85", b"\\u0085") + b"\n"


def finite(value):
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: finite(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [finite(item) for item in value]
    return value


def source_block() -> dict:
    return {
        "version": __version__,
        "install_id": str(get_system_setting("install_id")),
        "url": settings.SITE_URL,
        "locations_enabled": locations_enabled(),
    }


def single_row(serializer) -> dict | None:
    row = serializer.Meta.model.objects.order_by("id").first()
    return serializer(row).data if row else None


def export_params(request, serializer_class=ExportParamsSerializer) -> dict:
    params = serializer_class(data=request.query_params)
    params.is_valid(raise_exception=True)
    return params.validated_data


def finding_queryset(product: Product, *, external_issues: bool = False) -> QuerySet:
    if locations_enabled():
        endpoints = "locations__location__tags"
    else:
        endpoints = Prefetch(
            "status_finding",
            queryset=Endpoint_Status.objects.select_related("endpoint").prefetch_related("endpoint__tags"),
        )
    extra = {}
    if external_issues:
        transitions = Prefetch(
            "sonarqube_issue__sonarqube_issue_transition_set", queryset=Sonarqube_Issue_Transition.objects.order_by("id"),
        )
        extra = {"select": ("github_issue", "sonarqube_issue"), "prefetch": (transitions,)}
    return (
        Finding.objects.filter(test__engagement__product=product)
        .select_related("test", "test__test_type", *extra.get("select", ()))
        .prefetch_related(
            *extra.get("prefetch", ()),
            notes_prefetch(),
            vulnerability_id_prefetch(),
            "finding_cwe_set",
            "reviewers",
            "found_by",
            "risk_acceptance_set",
            "tags",
            "jira_issue",
            "finding_group_set__jira_issue",
            "files",
            Prefetch("burprawrequestresponse_set", queryset=BurpRawRequestResponse.objects.order_by("id")),
            "finding_meta",
            endpoints,
        )
    )


def check_list_prefetch() -> Prefetch:
    issues = [Prefetch(field, queryset=Finding.objects.only("id").order_by("id")) for field in CHECK_LIST_ISSUE_FIELDS]
    return Prefetch("eng_for_check", queryset=Check_List.objects.order_by("id").prefetch_related(*issues))


def risk_acceptance_in(product: Product, prefix: str = "") -> Q:
    # An acceptance belongs to a product through an engagement link or through a finding it accepts.
    return Q(**{f"{prefix}engagement__product": product}) | Q(**{f"{prefix}accepted_findings__test__engagement__product": product})


def import_history_lines(product: Product, counts: dict, render) -> Iterator[bytes]:
    imports = Test_Import.objects.filter(test__engagement__product=product).order_by("test_id", "id")
    # The same order as the imports, so one pass pairs each import with its group of actions.
    actions = (
        Test_Import_Finding_Action.objects.filter(test_import__test__engagement__product=product)
        .order_by("test_import__test_id", "test_import_id", "id")
        .values_list("test_import__test_id", "test_import_id", "finding_id", "action", "created", "modified")
    )
    # Start the actions query before the imports query. An import made in between then has no group of actions,
    # instead of a group of actions with no import.
    by_import = groupby(actions.iterator(chunk_size=EXPORT_CHUNK_SIZE), key=itemgetter(0, 1))
    pending = next(by_import, None)
    serializer = ExportTestImportSerializer()
    for test_import in imports.iterator(chunk_size=EXPORT_CHUNK_SIZE):
        counts["test_imports"] += 1
        yield render({"type": "test_import", "data": serializer.to_representation(test_import)})
        key = (test_import.test_id, test_import.id)
        # A group that sorts before this import belongs to an import deleted after the actions query started.
        while pending is not None and pending[0] < key:
            pending = next(by_import, None)
        if pending is None or pending[0] != key:
            continue
        for batch in batched(pending[1], ACTIONS_PER_LINE, strict=False):
            counts["test_import_actions"] += len(batch)
            rows = [
                [finding_id, action, render_datetime(created), render_datetime(modified)]
                for _, _, finding_id, action, created, modified in batch
            ]
            yield render({"type": "test_import_actions", "data": {"test_import": test_import.id, "actions": rows}})
        pending = next(by_import, None)


def audit_scope(model, product: Product) -> QuerySet:
    if model is Risk_Acceptance:
        return Risk_Acceptance.objects.filter(risk_acceptance_in(product))
    return model.objects.filter(**{AUDIT_PRODUCT_PATHS[model]: product.id})


def pages(queryset: QuerySet, ordering: tuple[str, ...], after) -> Iterator:
    """
    The rows in ``ordering``, one query per page of EXPORT_CHUNK_SIZE rows. ``after(row)`` selects the rows past it.

    A page holds no cursor open, so the database never keeps a copy of the whole result.
    """
    page = list(queryset.order_by(*ordering)[:EXPORT_CHUNK_SIZE])
    while page:
        yield from page
        if len(page) < EXPORT_CHUNK_SIZE:
            return
        page = list(queryset.filter(after(page[-1])).order_by(*ordering)[:EXPORT_CHUNK_SIZE])


def tracking_file_lines(product: Product, counts: dict, render) -> Iterator[bytes]:
    rows = pages(
        Objects_Product.objects.filter(product=product).select_related("review_status").prefetch_related("tags"),
        ("id",),
        lambda row: Q(id__gt=row.id),
    )
    serializer = ExportTrackingFileSerializer()
    for row in rows:
        counts["tracking_files"] += 1
        yield render({"type": "tracking_file", "data": serializer.to_representation(row)})


def benchmark_lines(product: Product, counts: dict, render, context: dict) -> Iterator[bytes]:
    summaries = {row.benchmark_type_id: row for row in Benchmark_Product_Summary.objects.filter(product=product)}
    rows = pages(
        Benchmark_Product.objects.filter(product=product)
        .annotate(benchmark_type_id=F("control__category__type_id"))
        .prefetch_related(notes_prefetch()),
        ("benchmark_type_id", "control_id"),
        lambda row: Q(benchmark_type_id__gte=row.benchmark_type_id)
        & (Q(benchmark_type_id__gt=row.benchmark_type_id) | Q(control_id__gt=row.control_id)),
    )
    serializer = ExportBenchmarkResultSerializer(many=True, context=context)

    def line(type_id: int, results: list) -> bytes:
        summary = summaries.get(type_id)
        counts["benchmarks"] += 1
        return render({
            "type": "benchmark",
            "data": {
                "benchmark_type": type_id,
                "desired_level": summary.desired_level if summary else None,
                "publish": summary.publish if summary else None,
                "controls": serializer.to_representation(results),
            },
        })

    # A type with a summary and no result still gets its line, in type order.
    waiting = sorted(summaries)
    for type_id, results in groupby(rows, key=attrgetter("benchmark_type_id")):
        while waiting and waiting[0] < type_id:
            yield line(waiting.pop(0), [])
        if waiting and waiting[0] == type_id:
            waiting.pop(0)
        yield line(type_id, list(results))
    for type_id in waiting:
        yield line(type_id, [])


def answered_survey_lines(product: Product, counts: dict, render) -> Iterator[bytes]:
    rows = pages(Answered_Survey.objects.filter(engagement__product=product), ("id",), lambda row: Q(id__gt=row.id))
    serializer = ExportAnsweredSurveySerializer()
    for page in batched(rows, EXPORT_CHUNK_SIZE, strict=False):
        surveys = list(page)
        prefetch_answers(surveys)
        for row in surveys:
            counts["answered_surveys"] += 1
            yield render({"type": "answered_survey", "data": serializer.to_representation(row)})


def product_endpoint_lines(product: Product, counts: dict, render) -> Iterator[bytes]:
    locations = locations_enabled()
    if locations:
        # A location is on a product once, so location_id also works as the paging key.
        rows = pages(
            LocationProductReference.objects.filter(product=product).select_related("location").prefetch_related(
                "location__tags",
                Prefetch(
                    "location__location_meta",
                    queryset=DojoMeta.objects.filter(Q(location_product=product) | Q(location_product=None)).order_by("id"),
                ),
            ),
            ("location_id",),
            lambda row: Q(location_id__gt=row.location_id),
        )
    else:
        rows = pages(
            Endpoint.objects.filter(product=product).prefetch_related(
                "tags", Prefetch("endpoint_meta", queryset=DojoMeta.objects.order_by("id")),
            ),
            ("id",),
            lambda row: Q(id__gt=row.id),
        )
    for row in rows:
        counts["product_endpoints"] += 1
        yield render({"type": "product_endpoint", "data": export_product_endpoint(row, product.id, locations=locations)})


def product_extras_lines(product: Product, counts: dict, render, context: dict) -> Iterator[bytes]:
    yield from tracking_file_lines(product, counts, render)
    yield from benchmark_lines(product, counts, render, context)
    yield from answered_survey_lines(product, counts, render)
    yield from product_endpoint_lines(product, counts, render)


def audit_history_lines(product: Product, counts: dict, render) -> Iterator[bytes]:
    for model in AUDIT_MODELS:
        events = audit_event_model(model).objects.filter(
            pgh_obj_id__in=audit_scope(model, product).values("id"),
        ).select_related("pgh_context")
        serializer = ExportAuditEventSerializer(model)
        rows = pages(
            events,
            ("pgh_obj_id", "pgh_id"),
            # Without the >= bound, Postgres scans every page from the start.
            lambda event: Q(pgh_obj_id__gte=event.pgh_obj_id)
            & (Q(pgh_obj_id__gt=event.pgh_obj_id) | Q(pgh_id__gt=event.pgh_id)),
        )
        for event in rows:
            counts["audit_events"] += 1
            yield render({"type": "audit_event", "data": serializer.to_representation(event)})
    content_types = ContentType.objects.get_for_models(*AUDIT_MODELS)
    # One query per model. In one query, an OR over the models stops Postgres from using the object_id index.
    per_model = [
        pages(
            LogEntry.objects.filter(
                content_type=content_types[model], object_id__in=audit_scope(model, product).values("id"),
            ).select_related("content_type"),
            ("id",),
            lambda entry: Q(id__gt=entry.id),
        )
        for model in AUDIT_MODELS
    ]
    serializer = ExportLegacyAuditEntrySerializer()
    for entry in heapq.merge(*per_model, key=attrgetter("id")):
        counts["legacy_audit_entries"] += 1
        yield render({"type": "legacy_audit_entry", "data": serializer.to_representation(entry)})


def product_lines(
    product: Product,
    request,
    max_file_bytes: int,
    *,
    import_history: bool = False,
    audit_history: bool = False,
    product_extras: bool = False,
    jira: bool = False,
    external_issues: bool = False,
) -> Iterator[bytes]:
    context = {"request": request, "max_file_bytes": max_file_bytes, "jira": jira, "external_issues": external_issues}
    render = NDJSONRenderer().render
    header_jira = {}
    if jira:
        projects = JIRA_Project.objects.filter(product=product, engagement=None).order_by("id")
        header_jira = {"jira_projects": ExportJiraProjectSerializer(projects, many=True).data}
    yield render({
        "type": "header",
        "schema": SCHEMA_VERSION,
        "generated_at": timezone.now().isoformat(),
        "max_file_bytes": max_file_bytes,
        "source": source_block(),
        "product": ExportProductSerializer(product, context=context).data,
        **header_jira,
        **(
            {
                "github_projects": ExportGithubProjectSerializer(
                    GITHUB_PKey.objects.filter(product=product).order_by("id"), many=True,
                ).data,
            }
            if external_issues else {}
        ),
        "engagement_presets": ExportEngagementPresetSerializer(
            Engagement_Presets.objects.filter(product=product).order_by("id").prefetch_related("test_type", "network_locations"),
            many=True,
        ).data,
        "api_scan_configurations": ExportAPIScanConfigurationSerializer(
            Product_API_Scan_Configuration.objects.filter(product=product).order_by("id"), many=True,
        ).data,
    })
    counts = dict.fromkeys(COUNT_KEYS, 0)
    finding_groups = set()
    sections = (
        (
            "engagement",
            ExportEngagementSerializer,
            Engagement.objects.filter(product=product).prefetch_related(
                notes_prefetch(), "risk_acceptance", "files", "tags", check_list_prefetch(),
                *(("jira_project", "jira_issue") if jira else ()),
            ),
        ),
        (
            "test",
            ExportTestSerializer,
            Test.objects.filter(engagement__product=product)
            .select_related("test_type")
            .prefetch_related(notes_prefetch(), "files", "tags", "finding_group_set__jira_issue"),
        ),
        ("finding", ExportFindingSerializer, finding_queryset(product, external_issues=external_issues)),
        (
            "risk_acceptance",
            ExportRiskAcceptanceSerializer,
            Risk_Acceptance.objects.filter(risk_acceptance_in(product))
            .distinct()
            .prefetch_related(
                notes_prefetch(), "engagement_set", Prefetch("accepted_findings", queryset=Finding.objects.only("id")),
            ),
        ),
    )
    for line_type, serializer_class, queryset in sections:
        serializer = serializer_class(context=context)
        ordering = ("test_id", "id") if line_type == "finding" else ("id",)
        for obj in queryset.order_by(*ordering).iterator(chunk_size=EXPORT_CHUNK_SIZE):
            data = serializer.to_representation(obj)
            files = data.get("files", [])
            counts[f"{line_type}s"] += 1
            counts["notes"] += len(data["notes"])
            if line_type == "engagement" and data["threat_model_file"]:
                files = [*files, data["threat_model_file"]]
            counts["files"] += len(files)
            counts["files_over_cap"] += sum(1 for entry in files if entry["data_base64"] is None and "error" not in entry)
            if line_type == "finding":
                counts["endpoints"] += len(data["endpoints"])
                finding_groups.update(group["id"] for group in data["finding_groups"])
            yield render({"type": line_type, "data": data})
    counts["finding_groups"] = len(finding_groups)
    if jira:
        counts.update(jira_stream_counts(product))
    if external_issues:
        counts.update(external_issue_counts(product))
    if product_extras:
        counts.update(dict.fromkeys(PRODUCT_EXTRAS_COUNT_KEYS, 0))
        counts["product_endpoints"] = 0
        yield from product_extras_lines(product, counts, render, context)
    if import_history:
        counts.update(dict.fromkeys(IMPORT_HISTORY_COUNT_KEYS, 0))
        yield from import_history_lines(product, counts, render)
    if audit_history:
        counts.update(dict.fromkeys(AUDIT_HISTORY_COUNT_KEYS, 0))
        yield from audit_history_lines(product, counts, render)
    yield render({"type": "end", "counts": counts})


def jira_issue_in(product: Product) -> Q:
    return (
        Q(finding__test__engagement__product=product)
        | Q(finding_group__test__engagement__product=product)
        | Q(engagement__product=product)
    )


def jira_stream_counts(product: Product) -> dict[str, int]:
    projects = JIRA_Project.objects.filter(Q(product=product, engagement=None) | Q(engagement__product=product))
    return {"jira_projects": projects.count(), "jira_issues": JIRA_Issue.objects.filter(jira_issue_in(product)).count()}


def external_issue_counts(product: Product) -> dict[str, int]:
    findings = Finding.objects.filter(test__engagement__product=product)
    return {
        "github_projects": GITHUB_PKey.objects.filter(product=product).count(),
        "github_issues": GITHUB_Issue.objects.filter(finding__in=findings).count(),
        "sonarqube_issues": findings.filter(sonarqube_issue__isnull=False).count(),
    }


def count_keys(
    *, import_history: bool, audit_history: bool, product_extras: bool, jira: bool = False, external_issues: bool = False,
) -> tuple[str, ...]:
    return (
        *COUNT_KEYS,
        *(JIRA_COUNT_KEYS if jira else ()),
        *(EXTERNAL_ISSUES_COUNT_KEYS if external_issues else ()),
        *(PRODUCT_EXTRAS_COUNT_KEYS if product_extras else ()),
        *(IMPORT_HISTORY_COUNT_KEYS if import_history else ()),
        *(AUDIT_HISTORY_COUNT_KEYS if audit_history else ()),
    )


def ids_by_product(model, prefix: str = "") -> dict[int, set[int]]:
    ids = defaultdict(set)
    for path in (f"{prefix}engagement__product_id", f"{prefix}accepted_findings__test__engagement__product_id"):
        for product_id, found in model.objects.order_by().values_list(path).annotate(ids=ArrayAgg("id", distinct=True)):
            if product_id is not None:
                ids[product_id].update(found)
    return ids


def add_audit_history_counts(counts: dict) -> None:
    content_types = ContentType.objects.get_for_models(*AUDIT_MODELS)
    for model in AUDIT_MODELS:
        events = audit_event_model(model).objects.order_by()
        entries = LogEntry.objects.filter(content_type=content_types[model]).order_by()
        if model is Risk_Acceptance:
            per_event = dict(events.values_list("pgh_obj_id").annotate(n=Count("pgh_id")))
            per_entry = dict(entries.values_list("object_id").annotate(n=Count("id")))
            for product_id, found in ids_by_product(Risk_Acceptance).items():
                counts[product_id]["audit_events"] += sum(per_event.get(pk, 0) for pk in found)
                counts[product_id]["legacy_audit_entries"] += sum(per_entry.get(pk, 0) for pk in found)
            continue
        path = AUDIT_PRODUCT_PATHS[model]
        object_product = Subquery(model.objects.filter(pk=OuterRef("object_id")).values(path)[:1])
        # An object that is gone has no product, so its events and entries add to no product of the manifest.
        for key, rows in (
            ("audit_events", events.values_list(f"pgh_obj__{path}").annotate(n=Count("pgh_id"))),
            ("legacy_audit_entries", entries.annotate(object_product=object_product).values_list("object_product").annotate(n=Count("id"))),
        ):
            for product_id, n in rows:
                if product_id is not None:
                    counts[product_id][key] += n


def add_benchmark_counts(counts: dict) -> None:
    # A type counts once per product, whether the product has a summary, a result or both for it.
    types = defaultdict(set)
    for product_id, type_id in Benchmark_Product_Summary.objects.order_by().values_list("product_id", "benchmark_type_id"):
        types[product_id].add(type_id)
    results = Benchmark_Product.objects.order_by().values_list("product_id", "control__category__type_id").distinct()
    for product_id, type_id in results:
        types[product_id].add(type_id)
    for product_id, found in types.items():
        counts[product_id]["benchmarks"] += len(found)


def product_counts(
    max_file_bytes: int, *, file_counts: bool, import_history: bool, audit_history: bool, product_extras: bool,
    jira: bool = False, external_issues: bool = False,
) -> dict[int, dict[str, int | None]]:
    keys = count_keys(
        import_history=import_history, audit_history=audit_history, product_extras=product_extras, jira=jira,
        external_issues=external_issues,
    )
    counts = defaultdict(lambda: {**dict.fromkeys(keys, 0), "files_over_cap": 0 if file_counts else None})
    sources = (
        ("engagements", Engagement, "product_id"),
        ("tests", Test, "engagement__product_id"),
        ("findings", Finding, "test__engagement__product_id"),
        ("endpoints", LocationProductReference if locations_enabled() else Endpoint, "product_id"),
        # Count M2M through rows: the stream counts a shared note once per owner, not once.
        ("notes", Engagement.notes.through, "engagement__product_id"),
        ("notes", Test.notes.through, "test__engagement__product_id"),
        ("notes", Finding.notes.through, "finding__test__engagement__product_id"),
        ("finding_groups", Finding_Group, "test__engagement__product_id"),
    )
    if product_extras:
        sources += (
            ("tracking_files", Objects_Product, "product_id"),
            ("answered_surveys", Answered_Survey, "engagement__product_id"),
        )
    if jira:
        sources += (
            ("jira_projects", JIRA_Project.objects.filter(engagement=None), "product_id"),
            ("jira_projects", JIRA_Project, "engagement__product_id"),
            ("jira_issues", JIRA_Issue, "finding__test__engagement__product_id"),
            ("jira_issues", JIRA_Issue, "finding_group__test__engagement__product_id"),
            ("jira_issues", JIRA_Issue, "engagement__product_id"),
        )
    if external_issues:
        sources += (
            ("github_projects", GITHUB_PKey, "product_id"),
            ("github_issues", GITHUB_Issue, "finding__test__engagement__product_id"),
            ("sonarqube_issues", Finding.objects.filter(sonarqube_issue__isnull=False), "test__engagement__product_id"),
        )
    if import_history:
        sources += (
            ("test_imports", Test_Import, "test__engagement__product_id"),
            ("test_import_actions", Test_Import_Finding_Action, "test_import__test__engagement__product_id"),
        )
    for key, model, product_path in sources:
        # order_by() drops default orderings, which would otherwise split the GROUP BY per row.
        manager = model if isinstance(model, QuerySet) else model.objects
        rows = manager.order_by().values_list(product_path).annotate(n=Count("id", distinct=True))
        for product_id, n in rows:
            if product_id is not None:
                counts[product_id][key] += n
    # A risk acceptance reaches a product through two paths, so collect ids per product and count the union.
    for key, model, prefix in (("risk_acceptances", Risk_Acceptance, ""), ("notes", Risk_Acceptance.notes.through, "risk_acceptance__")):
        for product_id, found in ids_by_product(model, prefix).items():
            counts[product_id][key] += len(found)
    if product_extras:
        add_benchmark_counts(counts)
    if audit_history:
        add_audit_history_counts(counts)
    storage = FileUpload._meta.get_field("file").storage
    over_cap = {}
    add_threat_model_counts(counts, max_file_bytes, file_counts=file_counts)
    file_sources = (
        (Engagement.files.through, "engagement__product_id"),
        (Test.files.through, "test__engagement__product_id"),
        (Finding.files.through, "finding__test__engagement__product_id"),
    )
    for through, product_path in file_sources:
        for product_id, file_id, name in through.objects.values_list(product_path, "fileupload_id", "fileupload__file"):
            counts[product_id]["files"] += 1
            if not file_counts:
                continue
            if file_id not in over_cap:
                size = file_size(storage, name)
                over_cap[file_id] = size is not None and size > max_file_bytes
            if over_cap[file_id]:
                counts[product_id]["files_over_cap"] += 1
    return counts


def add_threat_model_counts(counts: dict, max_file_bytes: int, *, file_counts: bool) -> None:
    for engagement in Engagement.objects.exclude(tmodel_path__in=("", "none")).exclude(tmodel_path=None).only(
        "id", "tmodel_path", "product_id",
    ):
        counts[engagement.product_id]["files"] += 1
        resolved = readable_threat_model(threat_model_file(engagement)) if file_counts else None
        if resolved and resolved.stat().st_size > max_file_bytes:
            counts[engagement.product_id]["files_over_cap"] += 1


def _summed(
    products: list[dict], *, file_counts: bool, import_history: bool, audit_history: bool, product_extras: bool,
    jira: bool = False, external_issues: bool = False,
) -> dict[str, int | None]:
    return {
        key: None if key == "files_over_cap" and not file_counts else sum(product["counts"][key] for product in products)
        for key in count_keys(
            import_history=import_history, audit_history=audit_history, product_extras=product_extras, jira=jira,
            external_issues=external_issues,
        )
    }


def _plain(value):
    return list(value) if isinstance(value, tuple) else value


def _set_by_customer(current: dict, shipped: dict, *, fallback) -> dict:
    effective = {key: _plain(current.get(key, fallback)) for key in current.keys() | shipped.keys()}
    return {
        key: effective[key]
        for key in sorted(effective)
        if key not in shipped or _plain(shipped[key]) != effective[key]
    }


def deduplication_rules() -> dict:
    return {
        "algorithm_per_parser": _set_by_customer(
            settings.DEDUPLICATION_ALGORITHM_PER_PARSER,
            settings.DEDUPLICATION_ALGORITHM_PER_PARSER_SHIPPED,
            fallback=settings.DEDUPE_ALGO_LEGACY,
        ),
        "hashcode_fields_per_scanner": _set_by_customer(
            settings.HASHCODE_FIELDS_PER_SCANNER, settings.HASHCODE_FIELDS_PER_SCANNER_SHIPPED, fallback=[],
        ),
        "hashcode_allows_null_cwe": _set_by_customer(
            settings.HASHCODE_ALLOWS_NULL_CWE, settings.HASHCODE_ALLOWS_NULL_CWE_SHIPPED, fallback=True,
        ),
    }


def questionnaires() -> list[dict]:
    rows = list(Engagement_Survey.objects.order_by("id"))
    prefetch_questions(rows)
    return ExportQuestionnaireSerializer(rows, many=True).data


def open_survey_responses() -> list[dict]:
    rows = list(Answered_Survey.objects.filter(engagement=None).order_by("id"))
    prefetch_answers(rows)
    return ExportAnsweredSurveySerializer(rows, many=True).data


def benchmark_types() -> list[dict]:
    requirements = Prefetch("benchmark_requirement_set", queryset=Benchmark_Requirement.objects.order_by("id"))
    categories = Prefetch(
        "benchmark_category_set", queryset=Benchmark_Category.objects.order_by("id").prefetch_related(requirements),
    )
    return ExportBenchmarkTypeSerializer(
        Benchmark_Type.objects.order_by("id").prefetch_related(categories), many=True,
    ).data


def build_manifest(
    request,
    max_file_bytes: int,
    *,
    file_counts: bool,
    import_history: bool = False,
    audit_history: bool = False,
    product_extras: bool = False,
    jira: bool = False,
    external_issues: bool = False,
) -> dict:
    counts = product_counts(
        max_file_bytes,
        file_counts=file_counts,
        import_history=import_history,
        audit_history=audit_history,
        product_extras=product_extras,
        jira=jira,
        external_issues=external_issues,
    )
    products = [
        {
            "id": product.id,
            "name": product.name,
            "prod_type": product.prod_type_id,
            "counts": counts[product.id],
            "description": product.description,
            "tags": [tag.name for tag in product.tags.all()],
            "business_criticality": product.business_criticality,
            "sla_configuration": product.sla_configuration_id,
            "product_manager": product.product_manager_id,
            "technical_contact": product.technical_contact_id,
            "team_manager": product.team_manager_id,
        }
        for product in Product.objects.order_by("id").prefetch_related("tags").only(
            "id", "name", "prod_type_id", "description", "business_criticality", "sla_configuration_id",
            "product_manager_id", "technical_contact_id", "team_manager_id",
        )
    ]
    members = defaultdict(list)
    for product in products:
        members[product["prod_type"]].append(product)
    product_types = [
        {
            "id": pk,
            "name": name,
            "counts": {
                "products": len(members[pk]),
                **_summed(
                    members[pk],
                    file_counts=file_counts,
                    import_history=import_history,
                    audit_history=audit_history,
                    product_extras=product_extras,
                    jira=jira,
                    external_issues=external_issues,
                ),
            },
        }
        for pk, name in Product_Type.objects.order_by("id").values_list("id", "name")
    ]
    users = (
        Dojo_User.objects.select_related("usercontactinfo", "auth_token")
        .prefetch_related(
            Prefetch("user_permissions", queryset=Permission.objects.select_related("content_type")),
            Prefetch("groups__permissions", queryset=Permission.objects.select_related("content_type")),
        )
        .order_by("id")
    )
    permission_names = configuration_permission_names()
    user_serializer = ExportUserSerializer(users, many=True, context={"configuration_permission_names": permission_names})
    return {
        "schema": SCHEMA_VERSION,
        "generated_at": timezone.now().isoformat(),
        "source": source_block(),
        "max_file_bytes": max_file_bytes,
        "token": {
            "username": request.user.username,
            "is_superuser": request.user.is_superuser,
            "expires_at": token_expires_at(request.auth) if isinstance(request.auth, Token) else None,
        },
        "features": ["check_lists", *HISTORY_FEATURES, "product_extras", "jira", "external_issues"],
        "deduplication": deduplication_rules(),
        "announcement": single_row(ExportAnnouncementSerializer),
        "login_banner": single_row(ExportLoginBannerSerializer),
        "scan_types": sorted(
            Test.objects.exclude(scan_type=None).order_by().values_list("scan_type", flat=True).distinct(),
        ),
        "reference": {
            **{
                key: serializer(serializer.Meta.model.objects.order_by("id"), many=True).data
                for key, serializer in REFERENCE_SERIALIZERS.items()
            },
            "users": user_serializer.data,
            "questionnaires": questionnaires(),
            "open_survey_responses": open_survey_responses(),
            "benchmark_types": benchmark_types(),
            "configuration_permissions": sorted(permission_names),
            **(
                {"github_configurations": ExportGithubConfigurationSerializer(GITHUB_Conf.objects.order_by("id"), many=True).data}
                if external_issues else {}
            ),
            **(
                {"jira_instances": ExportJiraInstanceSerializer(JIRA_Instance.objects.order_by("id"), many=True).data}
                if jira else {}
            ),
        },
        "product_types": product_types,
        "products": products,
        "totals": {
            "product_types": len(product_types),
            "products": len(products),
            **_summed(
                products,
                file_counts=file_counts,
                import_history=import_history,
                audit_history=audit_history,
                product_extras=product_extras,
                jira=jira,
                external_issues=external_issues,
            ),
        },
    }


class ProductExportView(APIView):
    permission_classes = (IsSuperUser,)
    renderer_classes = (JSONRenderer, NDJSONRenderer)

    @extend_schema(
        parameters=[ExportParamsSerializer, OpenApiParameter("id", OpenApiTypes.INT, OpenApiParameter.PATH)],
        responses={(200, "application/x-ndjson"): OpenApiTypes.STR},
        description=(
            "Superuser only. Streams one product with its engagements, tests, findings and risk acceptances "
            f"as NDJSON, one JSON object per line. The line shapes are documented at {DOCS_URL}"
        ),
    )
    def get(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        params = export_params(request)
        return StreamingHttpResponse(
            product_lines(
                product,
                request,
                params["max_file_bytes"],
                import_history=params["import_history"],
                audit_history=params["audit_history"],
                product_extras=params["product_extras"],
                jira=params["jira"],
                external_issues=params["external_issues"],
            ),
            content_type="application/x-ndjson",
            headers={
                "Content-Disposition": f'attachment; filename="defectdojo-product-{product.pk}-export.ndjson"',
                "X-Accel-Buffering": "no",
            },
        )


class ExportManifestView(APIView):
    permission_classes = (IsSuperUser,)
    renderer_classes = (JSONRenderer, NDJSONRenderer)

    @extend_schema(
        parameters=[ManifestParamsSerializer],
        responses={200: OpenApiTypes.OBJECT},
        description=(
            "Superuser only. Lists the product types and products with their counts, the reference data "
            f"and the users that a product export refers to. The keys are documented at {DOCS_URL}"
        ),
    )
    def get(self, request):
        params = export_params(request, ManifestParamsSerializer)
        return Response(
            build_manifest(
                request,
                params["max_file_bytes"],
                file_counts=params["file_counts"],
                import_history=params["import_history"],
                audit_history=params["audit_history"],
                product_extras=params["product_extras"],
                jira=params["jira"],
                external_issues=params["external_issues"],
            ),
        )
