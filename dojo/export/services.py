from django.conf import settings
from django.db.models import Count, Q

from dojo import __version__
from dojo.export import rows
from dojo.location.feature import locations_enabled
from dojo.location.models import LocationFindingReference
from dojo.models import (
    Development_Environment,
    Dojo_User,
    Endpoint_Status,
    Engagement,
    FileUpload,
    Finding,
    Finding_Group,
    Note_Type,
    Notes,
    Product,
    Product_Type,
    Regulation,
    Risk_Acceptance,
    SLA_Configuration,
    System_Settings,
    Test,
)

EXPORT_API_VERSION = 1
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FILE_BYTES_LIMIT = 64 * 1024 * 1024

NOT_EXPORTED = [
    "api_tokens",
    "sso_settings",
    "jira_instances",
    "tool_configurations",
    "notification_settings",
    "system_settings",
    "api_scan_configurations",
    "threat_model_files",
    "non_url_locations",
]

USER_REFERENCES = (
    (Finding, ("reporter", "mitigated_by", "last_reviewed_by", "review_requested_by", "defect_review_requested_by")),
    (Notes, ("author", "editor")),
    (Engagement, ("lead",)),
    (Test, ("lead",)),
    (Product, ("product_manager", "technical_contact", "team_manager")),
    (Risk_Acceptance, ("owner",)),
    (Finding_Group, ("creator",)),
    (Endpoint_Status, ("mitigated_by",)),
    (LocationFindingReference, ("auditor",)),
)


def instance_id() -> str:
    return str(System_Settings.objects.get().instance_id)


def referenced_user_ids() -> set[int]:
    ids: set[int] = set()
    for model, fields in USER_REFERENCES:
        for field in fields:
            ids.update(
                model.objects.exclude(**{f"{field}__isnull": True}).order_by().values_list(f"{field}_id", flat=True).distinct(),
            )
    ids.update(Finding.reviewers.through.objects.order_by().values_list("dojo_user_id", flat=True).distinct())
    return ids


def _owners(product: Product) -> list[str]:
    users = [product.product_manager, product.technical_contact, product.team_manager]
    return sorted({user.email for user in users if user and user.email})


def _products() -> list[dict]:
    products = (
        Product.objects.select_related("prod_type", "sla_configuration", "product_manager", "technical_contact", "team_manager")
        .prefetch_related("tags")
        .annotate(
            test_count=Count("engagement__test", distinct=True),
            finding_count=Count(
                "engagement__test__finding",
                filter=Q(engagement__test__finding__duplicate=False),
                distinct=True,
            ),
        )
        .order_by("id")
    )
    return [
        {
            "id": product.id,
            "name": product.name,
            "description": product.description or "",
            "prod_type": product.prod_type.name,
            "tags": sorted(tag.name for tag in product.tags.all()),
            "business_criticality": product.business_criticality or "",
            "owners": _owners(product),
            "sla_configuration": product.sla_configuration.name if product.sla_configuration else "",
            "tests": product.test_count,
            "findings": product.finding_count,
        }
        for product in products
    ]


def _scan_types() -> list[dict]:
    scan_rows = (
        Test.objects.values("test_type__name")
        .annotate(
            tests=Count("id", distinct=True),
            findings=Count("finding", filter=Q(finding__duplicate=False), distinct=True),
        )
        .order_by("test_type__name")
    )
    return [{"name": row["test_type__name"], "tests": row["tests"], "findings": row["findings"]} for row in scan_rows]


def _users(user_ids: set[int]) -> list[dict]:
    users = Dojo_User.objects.filter(id__in=user_ids).order_by("username")
    return [
        {
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_active": user.is_active,
        }
        for user in users
    ]


def _reference_data() -> dict:
    return {
        "note_types": list(
            Note_Type.objects.order_by("name").values("name", "description", "is_single", "is_active", "is_mandatory"),
        ),
        "development_environments": list(Development_Environment.objects.order_by("name").values("name")),
        "sla_configurations": [
            {key: value for key, value in row.items() if key != "id"}
            for row in SLA_Configuration.objects.order_by("name").values()
        ],
        "regulations": [
            {key: value for key, value in row.items() if key != "id"}
            for row in Regulation.objects.order_by("name").values()
        ],
    }


def _file_owner(upload: FileUpload) -> tuple[str, int]:
    for owner, model in (("finding", Finding), ("test", Test), ("engagement", Engagement)):
        owner_id = model.objects.filter(files=upload).values_list("id", flat=True).first()
        if owner_id is not None:
            return owner, owner_id
    return "none", 0


def _file_stats(max_file_bytes: int) -> tuple[int, list[dict]]:
    total, oversized = 0, []
    for upload in FileUpload.objects.order_by("id").iterator(chunk_size=500):
        size = rows.stored_size(upload.file) or 0
        total += size
        if size > max_file_bytes:
            owner, owner_id = _file_owner(upload)
            oversized.append({"id": upload.id, "title": upload.title, "size": size, "owner": owner, "owner_id": owner_id})
    for acceptance in Risk_Acceptance.objects.exclude(path="").order_by("id").iterator(chunk_size=500):
        size = rows.stored_size(acceptance.path) or 0
        total += size
        if size > max_file_bytes:
            oversized.append({
                "id": acceptance.id, "title": acceptance.name, "size": size,
                "owner": "risk_acceptance", "owner_id": acceptance.id,
            })
    return total, oversized


def _dedupe(scan_types: list[dict]) -> dict:
    algorithms = settings.DEDUPLICATION_ALGORITHM_PER_PARSER
    fields = settings.HASHCODE_FIELDS_PER_SCANNER
    return {
        entry["name"]: {
            "algorithm": algorithms.get(entry["name"], settings.DEDUPE_ALGO_LEGACY),
            "hash_fields": list(fields.get(entry["name"], [])),
        }
        for entry in scan_types
    }


def _counts(user_ids: set[int], file_bytes: int) -> dict:
    return {
        "product_types": Product_Type.objects.count(),
        "products": Product.objects.count(),
        "engagements": Engagement.objects.count(),
        "tests": Test.objects.count(),
        "findings": Finding.objects.filter(duplicate=False).count(),
        "duplicate_findings": Finding.objects.filter(duplicate=True).count(),
        "notes": Notes.objects.count(),
        "files": FileUpload.objects.count(),
        "file_bytes": file_bytes,
        "risk_acceptances": Risk_Acceptance.objects.count(),
        "finding_groups": Finding_Group.objects.count(),
        "users": len(user_ids),
    }


def build_manifest(*, max_file_bytes: int) -> dict:
    scan_types = _scan_types()
    user_ids = referenced_user_ids()
    file_bytes, oversized_files = _file_stats(max_file_bytes)
    return {
        "export_api_version": EXPORT_API_VERSION,
        "defectdojo_version": __version__,
        "instance_id": instance_id(),
        "locations_enabled": locations_enabled(),
        "max_file_bytes": max_file_bytes,
        "counts": _counts(user_ids, file_bytes),
        "products": _products(),
        "scan_types": scan_types,
        "users": _users(user_ids),
        "reference_data": _reference_data(),
        "oversized_files": oversized_files,
        "dedupe": _dedupe(scan_types),
        "not_exported": NOT_EXPORTED,
    }
