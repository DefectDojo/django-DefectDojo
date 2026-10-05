import base64
import binascii
import json
from collections.abc import Iterator
from dataclasses import dataclass

from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import Count, Prefetch, Q

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
    (Finding, rows.FINDING_USER_FIELDS),
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


DEFAULT_PAGE_LIMIT = 1000
MAX_PAGE_LIMIT = 5000
PAGE_BYTE_BUDGET = 64 * 1024 * 1024

START = "start"
ENGAGEMENTS = "engagements"
TESTS = "tests"
GROUPS = "groups"
RISK_ACCEPTANCES = "risk_acceptances"
PHASES = (START, ENGAGEMENTS, TESTS, GROUPS, RISK_ACCEPTANCES)
NOTE_PREFETCH = ("notes__author", "notes__editor", "notes__note_type")


@dataclass(frozen=True)
class Cursor:
    phase: str = START
    test_id: int = 0
    after: int = 0
    high: int = 0

    def encode(self) -> str:
        raw = json.dumps(
            {"p": self.phase, "t": self.test_id, "a": self.after, "h": self.high}, separators=(",", ":"),
        )
        return base64.urlsafe_b64encode(raw.encode()).decode()

    @classmethod
    def decode(cls, value: str) -> "Cursor":
        if not value:
            return cls()
        try:
            data = json.loads(base64.urlsafe_b64decode(value.encode()))
            cursor = cls(
                phase=str(data["p"]), test_id=int(data["t"]), after=int(data["a"]), high=int(data["h"]),
            )
        except (ValueError, KeyError, TypeError, OverflowError, binascii.Error) as error:
            msg = "invalid cursor"
            raise ValueError(msg) from error
        if cursor.phase not in PHASES:
            msg = "invalid cursor"
            raise ValueError(msg)
        return cursor


@dataclass(frozen=True)
class ExportOptions:
    limit: int = DEFAULT_PAGE_LIMIT
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    include_duplicates: bool = False


class _Budget:
    def __init__(self, limit: int):
        self.limit = limit
        self.items = 0
        self.bytes = 0
        self.next: Cursor | None = None

    def full(self) -> bool:
        return self.items >= self.limit or self.bytes >= PAGE_BYTE_BUDGET

    def room(self) -> int:
        return max(self.limit - self.items, 0) + 1

    def spend(self, line: str, *, counted: bool = True) -> str:
        if counted:
            self.items += 1
        self.bytes += len(line)
        return line

    def stop(self, cursor: Cursor) -> None:
        self.next = cursor


def _line(payload: dict) -> str:
    return json.dumps(payload, cls=DjangoJSONEncoder, separators=(",", ":")) + "\n"


def _findings(test, after: int, high: int, options: ExportOptions):
    queryset = Finding.objects.filter(test=test, id__gt=after, id__lte=high).order_by("id")
    if not options.include_duplicates:
        queryset = queryset.filter(duplicate=False)
    return queryset.select_related(*rows.FINDING_USER_FIELDS).prefetch_related(*rows.finding_prefetch())


def _walk_engagements(product, cursor: Cursor, options: ExportOptions, budget: _Budget):
    queryset = (
        Engagement.objects.filter(product=product, id__gt=cursor.after)
        .order_by("id")
        .select_related("lead")
        .prefetch_related("tags", "files", *NOTE_PREFETCH)
    )
    last_id = cursor.after
    for engagement in queryset.iterator(chunk_size=200):
        if budget.full():
            budget.stop(Cursor(ENGAGEMENTS, after=last_id, high=cursor.high))
            return
        yield budget.spend(_line({
            "kind": "engagement",
            "id": engagement.id,
            "data": rows.engagement_row(engagement, options.max_file_bytes),
        }), counted=False)
        last_id = engagement.id


def _walk_tests(product, cursor: Cursor, options: ExportOptions, budget: _Budget):
    queryset = (
        Test.objects.filter(engagement__product=product, id__gte=cursor.test_id)
        .order_by("id")
        .select_related("lead", "test_type", "environment")
        .prefetch_related("tags", "files", *NOTE_PREFETCH)
    )
    for test in queryset.iterator(chunk_size=200):
        after = cursor.after if test.id == cursor.test_id else 0
        if after == 0:
            if budget.full():
                budget.stop(Cursor(TESTS, test_id=test.id, high=cursor.high))
                return
            yield budget.spend(_line({
                "kind": "test",
                "id": test.id,
                "engagement_id": test.engagement_id,
                "data": rows.test_row(test, options.max_file_bytes),
            }), counted=False)
        last_id = after
        findings = _findings(test, after, cursor.high, options)[: budget.room()]
        for index, finding in enumerate(findings.iterator(chunk_size=200)):
            if index and budget.full():
                budget.stop(Cursor(TESTS, test_id=test.id, after=last_id, high=cursor.high))
                return
            yield budget.spend(_line({
                "kind": "finding",
                "id": finding.id,
                "test_id": test.id,
                "data": rows.finding_row(finding, options.max_file_bytes),
            }))
            last_id = finding.id


def _walk_groups(product, cursor: Cursor, options: ExportOptions, budget: _Budget):
    queryset = (
        Finding_Group.objects.filter(test__engagement__product=product, id__gt=cursor.after)
        .order_by("id")
        .select_related("creator")
        .prefetch_related(Prefetch("findings", queryset=Finding.objects.only("id")))
    )
    last_id = cursor.after
    for group in queryset.iterator(chunk_size=200):
        if budget.full():
            budget.stop(Cursor(GROUPS, after=last_id, high=cursor.high))
            return
        yield budget.spend(_line({
            "kind": "finding_group",
            "id": group.id,
            "test_id": group.test_id,
            "data": {
                "name": group.name,
                "created": rows.plain(group.created),
                "modified": rows.plain(group.modified),
                "creator": rows.username(group.creator),
                "finding_ids": sorted(finding.id for finding in group.findings.all()),
            },
        }))
        last_id = group.id


def _walk_risk_acceptances(product, cursor: Cursor, options: ExportOptions, budget: _Budget):
    queryset = (
        Risk_Acceptance.objects.filter(engagement__product=product, id__gt=cursor.after)
        .distinct()
        .order_by("id")
        .select_related("owner")
        .prefetch_related(
            Prefetch("accepted_findings", queryset=Finding.objects.only("id")), "engagement_set", *NOTE_PREFETCH,
        )
    )
    last_id = cursor.after
    for acceptance in queryset.iterator(chunk_size=200):
        if budget.full():
            budget.stop(Cursor(RISK_ACCEPTANCES, after=last_id, high=cursor.high))
            return
        proof = None
        if acceptance.path:
            proof = rows.file_row(f"ra-{acceptance.id}", acceptance.name, acceptance.path, options.max_file_bytes)
        yield budget.spend(_line({
            "kind": "risk_acceptance",
            "id": acceptance.id,
            "data": {
                **rows.scalar_fields(acceptance, skip={"id"}),
                "owner": rows.username(acceptance.owner),
                "engagement_ids": sorted(engagement.id for engagement in acceptance.engagement_set.all()),
                "accepted_finding_ids": sorted(finding.id for finding in acceptance.accepted_findings.all()),
                "notes": [rows.note_row(note) for note in acceptance.notes.all()],
                "proof": proof,
            },
        }))
        last_id = acceptance.id


WALKERS = (
    (ENGAGEMENTS, _walk_engagements),
    (TESTS, _walk_tests),
    (GROUPS, _walk_groups),
    (RISK_ACCEPTANCES, _walk_risk_acceptances),
)


def product_counts(product, high: int, options: ExportOptions) -> dict:
    findings = Finding.objects.filter(test__engagement__product=product, id__lte=high)
    if not options.include_duplicates:
        findings = findings.filter(duplicate=False)
    return {
        "engagements": Engagement.objects.filter(product=product).count(),
        "tests": Test.objects.filter(engagement__product=product).count(),
        "findings": findings.count(),
        "finding_groups": Finding_Group.objects.filter(test__engagement__product=product).count(),
        "risk_acceptances": Risk_Acceptance.objects.filter(engagement__product=product).distinct().count(),
    }


def product_page(product, cursor: Cursor, options: ExportOptions) -> Iterator[str]:
    budget = _Budget(options.limit)
    yield _line({
        "kind": "header",
        "export_api_version": EXPORT_API_VERSION,
        "instance_id": instance_id(),
        "product_id": product.id,
        "locations_enabled": locations_enabled(),
    })
    if cursor.phase == START:
        high = Finding.objects.order_by("-id").values_list("id", flat=True).first() or 0
        yield budget.spend(_line({"kind": "product", "id": product.id, "data": rows.product_row(product)}), counted=False)
        cursor = Cursor(ENGAGEMENTS, high=high)
    started = False
    for phase, walker in WALKERS:
        if not started and phase != cursor.phase:
            continue
        phase_cursor = cursor if not started else Cursor(phase, high=cursor.high)
        started = True
        yield from walker(product, phase_cursor, options, budget)
        if budget.next is not None:
            yield _line({"kind": "page", "next": budget.next.encode()})
            return
    yield _line({"kind": "end", "counts": product_counts(product, cursor.high, options)})
