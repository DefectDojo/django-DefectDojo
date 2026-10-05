import base64
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from uuid import UUID

from django.db import models


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
