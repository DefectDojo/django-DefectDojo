import base64
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from uuid import UUID

from django.db import models
from django.db.models import Prefetch
from django.db.models.functions import Length
from django.utils import timezone

from dojo.location.feature import locations_enabled
from dojo.location.status import FindingLocationStatus
from dojo.models import BurpRawRequestResponse
from dojo.url.models import URL


def plain(value):
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Decimal | UUID):
        return str(value)
    if isinstance(value, bytes | memoryview):
        return base64.b64encode(bytes(value)).decode()
    return value


def scalar_fields(instance, skip=frozenset()) -> dict:
    return {
        field.name: plain(field.value_from_object(instance))
        for field in instance._meta.concrete_fields
        if not field.is_relation and not isinstance(field, models.FileField) and field.name not in skip
    }


def username(user) -> str | None:
    return user.username if user else None


def tag_names(instance) -> list[str]:
    return sorted(tag.name for tag in instance.tags.all())


def lookup_value(instance, field_name: str):
    value = getattr(instance, field_name, None)
    return getattr(value, "value", value)


def note_row(note) -> dict:
    return {
        "id": str(note.id),
        "entry": note.entry,
        "date": plain(note.date),
        "author": username(note.author),
        "private": note.private,
        "edited": note.edited,
        "editor": username(note.editor),
        "edit_time": plain(note.edit_time),
        "note_type": note.note_type.name if note.note_type else None,
    }


def stored_size(field_file) -> int | None:
    if not field_file:
        return None
    try:
        return field_file.size
    except Exception:
        return None


def file_row(file_id, title, field_file, max_file_bytes: int) -> dict:
    row = {"id": str(file_id), "title": title, "name": Path(field_file.name).name if field_file else ""}
    size = stored_size(field_file)
    if size is None:
        return {**row, "size": 0, "omitted": "missing"}
    row["size"] = size
    if size > max_file_bytes:
        return {**row, "omitted": "too_large"}
    return row


def product_row(product) -> dict:
    return {
        **scalar_fields(product, skip={"id"}),
        "prod_type": {"name": product.prod_type.name, **scalar_fields(product.prod_type, skip={"id", "name"})},
        "sla_configuration": product.sla_configuration.name if product.sla_configuration else None,
        "product_manager": username(product.product_manager),
        "technical_contact": username(product.technical_contact),
        "team_manager": username(product.team_manager),
        "platform": lookup_value(product, "platform"),
        "lifecycle": lookup_value(product, "lifecycle"),
        "origin": lookup_value(product, "origin"),
        "regulations": sorted(regulation.name for regulation in product.regulations.all()),
        "tags": tag_names(product),
        "meta": [{"name": meta.name, "value": meta.value} for meta in product.product_meta.all()],
    }


def engagement_row(engagement, max_file_bytes: int) -> dict:
    return {
        **scalar_fields(engagement, skip={"id", "updated"}),
        "lead": username(engagement.lead),
        "tags": tag_names(engagement),
        "notes": [note_row(note) for note in engagement.notes.all()],
        "files": [file_row(upload.id, upload.title, upload.file, max_file_bytes) for upload in engagement.files.all()],
    }


def test_row(test, max_file_bytes: int) -> dict:
    return {
        **scalar_fields(test, skip={"id", "updated"}),
        "test_type": test.test_type.name,
        "lead": username(test.lead),
        "environment": test.environment.name if test.environment else None,
        "tags": tag_names(test),
        "notes": [note_row(note) for note in test.notes.all()],
        "files": [file_row(upload.id, upload.title, upload.file, max_file_bytes) for upload in test.files.all()],
    }


FINDING_SKIP = frozenset({"id", "created", "updated", "hash_code"})
FINDING_USER_FIELDS = (
    "reporter",
    "mitigated_by",
    "last_reviewed_by",
    "review_requested_by",
    "defect_review_requested_by",
)
ENDPOINT_STATUS_FLAGS = (
    ("risk_accepted", FindingLocationStatus.RiskAccepted),
    ("false_positive", FindingLocationStatus.FalsePositive),
    ("out_of_scope", FindingLocationStatus.OutOfScope),
    ("mitigated", FindingLocationStatus.Mitigated),
)


PAIR_BATCH_FINDINGS = 200


def finding_prefetch() -> list[str | Prefetch]:
    paths = [
        "tags",
        "reviewers",
        "found_by",
        "notes__author",
        "notes__editor",
        "notes__note_type",
        "files",
        "vulnerability_references__vulnerability",
        "finding_cwe_set",
        "finding_meta",
        Prefetch(
            "burprawrequestresponse_set",
            queryset=BurpRawRequestResponse.objects.only("id", "finding")
            .annotate(size=Length("burpRequestBase64") + Length("burpResponseBase64"))
            .order_by("id"),
            to_attr="pair_sizes",
        ),
    ]
    if locations_enabled():
        return [*paths, "locations__location", "locations__auditor"]
    return [*paths, "status_finding__endpoint", "status_finding__mitigated_by"]


def _kept_pair_ids(pair_sizes, max_pair_bytes: int) -> tuple[list[int], int]:
    kept, total = [], 0
    for pair in pair_sizes:
        if not max_pair_bytes or total + pair.size > max_pair_bytes:
            break
        kept.append(pair.id)
        total += pair.size
    return kept, total


def _load_pairs(batch):
    ids = [pair_id for _, kept, _ in batch for pair_id in kept]
    content = {
        pair_id: (request, response)
        for pair_id, request, response in BurpRawRequestResponse.objects.filter(id__in=ids).values_list(
            "id", "burpRequestBase64", "burpResponseBase64",
        )
    }
    for finding, kept, omitted in batch:
        pairs = [content.pop(pair_id) for pair_id in kept if pair_id in content]
        yield finding, [
            {"request_b64": bytes(request).decode(), "response_b64": bytes(response).decode()}
            for request, response in pairs
        ], omitted


def with_pairs(findings, max_pair_bytes: int):
    """Yield each finding with its kept request and response pairs and the count of pairs left out."""
    batch, batch_bytes = [], 0
    for finding in findings:
        kept, size = _kept_pair_ids(finding.pair_sizes, max_pair_bytes)
        if batch and (batch_bytes + size > max_pair_bytes or len(batch) == PAIR_BATCH_FINDINGS):
            yield from _load_pairs(batch)
            batch, batch_bytes = [], 0
        batch.append((finding, kept, len(finding.pair_sizes) - len(kept)))
        batch_bytes += size
    yield from _load_pairs(batch)


def _endpoint_status(status) -> str:
    for flag, value in ENDPOINT_STATUS_FLAGS:
        if getattr(status, flag):
            return str(value)
    return str(FindingLocationStatus.Active)


def location_rows(finding) -> list[dict]:
    if locations_enabled():
        return [
            {
                "type": reference.location.location_type,
                "value": str(reference.location),
                "status": str(reference.status),
                "date": plain(timezone.localdate(reference.created, timezone.get_default_timezone())),
                "status_date": plain(reference.audit_time),
                "actor": username(reference.auditor),
            }
            for reference in finding.locations.all()
            if reference.location.location_type == URL.LOCATION_TYPE
        ]
    return [
        {
            "type": "url",
            "value": str(status.endpoint),
            "status": _endpoint_status(status),
            "date": plain(status.date),
            "status_date": plain(status.mitigated_time),
            "actor": username(status.mitigated_by),
        }
        for status in finding.status_finding.all()
    ]


def finding_row(finding, max_file_bytes: int, pairs: list[dict], pairs_omitted: int) -> dict:
    return {
        "fields": scalar_fields(finding, skip=FINDING_SKIP),
        "created": plain(finding.created),
        "updated": plain(finding.updated),
        "hash_code": finding.hash_code,
        "duplicate_finding_id": finding.duplicate_finding_id,
        "users": {name: username(getattr(finding, name)) for name in FINDING_USER_FIELDS},
        "tags": tag_names(finding),
        "vulnerability_ids": list(finding.vulnerability_ids),
        "cwes": list(finding.cwes),
        "reviewers": sorted(user.username for user in finding.reviewers.all()),
        "found_by": sorted(test_type.name for test_type in finding.found_by.all()),
        "locations": location_rows(finding),
        "request_response": pairs,
        "request_response_omitted": pairs_omitted,
        "notes": [note_row(note) for note in finding.notes.all()],
        "files": [file_row(upload.id, upload.title, upload.file, max_file_bytes) for upload in finding.files.all()],
        "meta": [{"name": meta.name, "value": meta.value} for meta in finding.finding_meta.all()],
    }
