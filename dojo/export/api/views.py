import heapq
import math
from collections import defaultdict
from collections.abc import Iterator
from itertools import batched, groupby
from operator import attrgetter, itemgetter

from auditlog.models import LogEntry
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.contrib.postgres.aggregates import ArrayAgg
from django.db.models import Count, OuterRef, Prefetch, Q, QuerySet, Subquery
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
    ExportAPIScanConfigurationSerializer,
    ExportAuditEventSerializer,
    ExportContactSerializer,
    ExportEngagementPresetSerializer,
    ExportEngagementSerializer,
    ExportFindingSerializer,
    ExportLegacyAuditEntrySerializer,
    ExportLoginBannerSerializer,
    ExportParamsSerializer,
    ExportProductSerializer,
    ExportReportTypeSerializer,
    ExportRiskAcceptanceSerializer,
    ExportTestImportSerializer,
    ExportTestSerializer,
    ExportTestTypeSerializer,
    ExportToolConfigurationSerializer,
    ExportUserSerializer,
    ManifestParamsSerializer,
    audit_event_model,
    file_size,
    render_datetime,
)
from dojo.finding.api.serializer import FindingTemplateSerializer
from dojo.location.feature import locations_enabled
from dojo.location.models import LocationProductReference
from dojo.models import (
    BurpRawRequestResponse,
    Check_List,
    Dojo_User,
    Endpoint,
    Engagement,
    Engagement_Presets,
    FileUpload,
    Finding,
    Finding_Group,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Risk_Acceptance,
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


def finding_queryset(product: Product) -> QuerySet:
    if locations_enabled():
        endpoints = "locations__location__tags"
    else:
        endpoints = Prefetch(
            "status_finding",
            queryset=Endpoint_Status.objects.select_related("endpoint").prefetch_related("endpoint__tags"),
        )
    return (
        Finding.objects.filter(test__engagement__product=product)
        .select_related("test", "test__test_type")
        .prefetch_related(
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
        .values_list("test_import_id", "finding_id", "action", "created", "modified")
    )
    # Start the actions query before the imports query. An import made in between then has no group of actions,
    # instead of a group of actions with no import.
    by_import = groupby(actions.iterator(chunk_size=EXPORT_CHUNK_SIZE), key=itemgetter(0))
    pending = next(by_import, None)
    serializer = ExportTestImportSerializer()
    for test_import in imports.iterator(chunk_size=EXPORT_CHUNK_SIZE):
        counts["test_imports"] += 1
        yield render({"type": "test_import", "data": serializer.to_representation(test_import)})
        if pending is None or pending[0] != test_import.id:
            continue
        for batch in batched(pending[1], ACTIONS_PER_LINE, strict=False):
            counts["test_import_actions"] += len(batch)
            rows = [
                [finding_id, action, render_datetime(created), render_datetime(modified)]
                for _, finding_id, action, created, modified in batch
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


def audit_history_lines(product: Product, counts: dict, render) -> Iterator[bytes]:
    for model in AUDIT_MODELS:
        events = audit_event_model(model).objects.filter(
            pgh_obj_id__in=audit_scope(model, product).values("id"),
        ).select_related("pgh_context")
        serializer = ExportAuditEventSerializer(model)
        rows = pages(
            events,
            ("pgh_obj_id", "pgh_id"),
            lambda event: Q(pgh_obj_id__gt=event.pgh_obj_id) | Q(pgh_obj_id=event.pgh_obj_id, pgh_id__gt=event.pgh_id),
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
    product: Product, request, max_file_bytes: int, *, import_history: bool = False, audit_history: bool = False,
) -> Iterator[bytes]:
    context = {"request": request, "max_file_bytes": max_file_bytes}
    render = NDJSONRenderer().render
    yield render({
        "type": "header",
        "schema": SCHEMA_VERSION,
        "generated_at": timezone.now().isoformat(),
        "max_file_bytes": max_file_bytes,
        "source": source_block(),
        "product": ExportProductSerializer(product, context=context).data,
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
            ),
        ),
        (
            "test",
            ExportTestSerializer,
            Test.objects.filter(engagement__product=product)
            .select_related("test_type")
            .prefetch_related(notes_prefetch(), "files", "tags", "finding_group_set__jira_issue"),
        ),
        ("finding", ExportFindingSerializer, finding_queryset(product)),
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
            counts["files"] += len(files)
            counts["files_over_cap"] += sum(1 for entry in files if entry["data_base64"] is None and "error" not in entry)
            if line_type == "finding":
                counts["endpoints"] += len(data["endpoints"])
                finding_groups.update(group["id"] for group in data["finding_groups"])
            yield render({"type": line_type, "data": data})
    counts["finding_groups"] = len(finding_groups)
    if import_history:
        counts.update(dict.fromkeys(IMPORT_HISTORY_COUNT_KEYS, 0))
        yield from import_history_lines(product, counts, render)
    if audit_history:
        counts.update(dict.fromkeys(AUDIT_HISTORY_COUNT_KEYS, 0))
        yield from audit_history_lines(product, counts, render)
    yield render({"type": "end", "counts": counts})


def count_keys(*, import_history: bool, audit_history: bool) -> tuple[str, ...]:
    return (
        *COUNT_KEYS,
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


def product_counts(
    max_file_bytes: int, *, file_counts: bool, import_history: bool, audit_history: bool,
) -> dict[int, dict[str, int | None]]:
    keys = count_keys(import_history=import_history, audit_history=audit_history)
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
    if import_history:
        sources += (
            ("test_imports", Test_Import, "test__engagement__product_id"),
            ("test_import_actions", Test_Import_Finding_Action, "test_import__test__engagement__product_id"),
        )
    for key, model, product_path in sources:
        # order_by() drops default orderings, which would otherwise split the GROUP BY per row.
        rows = model.objects.order_by().values_list(product_path).annotate(n=Count("id", distinct=True))
        for product_id, n in rows:
            if product_id is not None:
                counts[product_id][key] += n
    # A risk acceptance reaches a product through two paths, so collect ids per product and count the union.
    for key, model, prefix in (("risk_acceptances", Risk_Acceptance, ""), ("notes", Risk_Acceptance.notes.through, "risk_acceptance__")):
        for product_id, found in ids_by_product(model, prefix).items():
            counts[product_id][key] += len(found)
    if audit_history:
        add_audit_history_counts(counts)
    storage = FileUpload._meta.get_field("file").storage
    over_cap = {}
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


def _summed(products: list[dict], *, file_counts: bool, import_history: bool, audit_history: bool) -> dict[str, int | None]:
    return {
        key: None if key == "files_over_cap" and not file_counts else sum(product["counts"][key] for product in products)
        for key in count_keys(import_history=import_history, audit_history=audit_history)
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


def build_manifest(
    request, max_file_bytes: int, *, file_counts: bool, import_history: bool = False, audit_history: bool = False,
) -> dict:
    counts = product_counts(max_file_bytes, file_counts=file_counts, import_history=import_history, audit_history=audit_history)
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
                **_summed(members[pk], file_counts=file_counts, import_history=import_history, audit_history=audit_history),
            },
        }
        for pk, name in Product_Type.objects.order_by("id").values_list("id", "name")
    ]
    users = Dojo_User.objects.select_related("usercontactinfo", "auth_token").order_by("id")
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
        "features": ["check_lists", *HISTORY_FEATURES],
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
            "users": ExportUserSerializer(users, many=True).data,
        },
        "product_types": product_types,
        "products": products,
        "totals": {
            "product_types": len(product_types),
            "products": len(products),
            **_summed(products, file_counts=file_counts, import_history=import_history, audit_history=audit_history),
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
            ),
        )
