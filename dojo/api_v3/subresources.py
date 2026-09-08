"""
Generic notes / tags / files sub-resource router factories for API v3 (§4.12, OS5).

Three router factories (I5), each **parameterized by the parent resource** so this kernel module
imports **no parent-resource model** (finding/product/engagement/test/...): the parent's URL path
segment, a human label, its authorized-view queryset resolver, and the RBAC permission values all
arrive as factory arguments. The only models imported here are the sub-resources' *own* storage
models (``Notes``/``NoteHistory``/``FileUpload``) plus the shared authorization/file helpers -- the
factory legitimately owns those.

**Authorization is inherited from the parent, mirroring the v2 related-object permission classes**
(``UserHas*NotePermission`` / ``*FilePermission`` / ``*RelatedObjectPermission``):

1. the parent is resolved through its ``get_authorized_*`` view queryset -- an unknown *or
   unauthorized* parent is a **404** (never leak existence, §4.10);
2. the applicable per-method permission is then checked on the parent via ``user_has_permission``
   -- failure is a **403**. The permission *values* mirror v2 exactly:

   =========  ============================  =====================================
   sub-res    read (GET)                    write
   =========  ============================  =====================================
   notes      ``view``                      POST create -> ``view``  (v2 note post_permission)
   tags       ``view``                      PUT/POST/DELETE -> ``edit``
   files      ``Product_Tracking_Files_View``  POST -> ``Product_Tracking_Files_Add``
   =========  ============================  =====================================

Routes are thin (I6). Sub-resource lists are parent-scoped and simple -- no expand/fields/filter
machinery, only the shared pagination envelope (§12); therefore no FilterSpecs and no snapshot
regeneration.

**Note side-effects stay out of the kernel (I5/I6).** v2's per-resource notes ``@action`` fires
resource-specific side-effects on create (finding: JIRA comment sync + ``last_reviewed`` stamping +
@mention notifications; engagement/test: @mention notifications only). To reach v2 parity without
importing any JIRA/notification machinery here, ``build_notes_router`` takes an optional
``on_note_created(parent, note, *, user)`` callback, invoked *after* the note is persisted and linked
to the parent. The callback is a resource **service** function (``dojo/<resource>/services.py``) that
owns all such side-effects; the kernel merely calls it.

Inner view functions are registered manually (not via ``@router.get``) so each can be given a
unique ``__name__`` per resource -- the factory is called once per parent resource, and identical
closure names would otherwise collide into duplicate OpenAPI ``operationId``s.
"""
from __future__ import annotations

from datetime import datetime  # noqa: TC003 -- runtime import: ninja/pydantic resolves the schema field types
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import HttpResponse
from ninja import File, Form, Router, Schema
from ninja.constants import NOT_SET
from ninja.files import UploadedFile  # noqa: TC002 -- runtime import: ninja resolves the File() param type

from dojo.api_v3.errors import json_response, not_found_problem, validation_problem
from dojo.api_v3.pagination import paginate
from dojo.api_v3.refs import Ref, to_ref
from dojo.authorization.authorization import user_has_permission
from dojo.file_uploads.models import FileUpload
from dojo.notes.models import NoteHistory, Notes
from dojo.utils import generate_file_response

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import Model, QuerySet
    from django.http import HttpRequest


# --- Schemas (documentation only; runtime serialization is manual) ----------------------------

class NoteSchema(Schema):

    """A note (§4.12). ``created`` maps to ``Notes.date``; ``updated`` to ``Notes.edit_time`` (§12)."""

    id: int
    entry: str
    author: Ref | None
    private: bool
    edited: bool
    created: datetime | None
    updated: datetime | None


class NoteCreate(Schema):

    """POST body for a note (§4.12). ``note_type`` is out of the alpha write surface (§12)."""

    model_config = {"extra": "forbid"}

    entry: str
    private: bool = False


class NoteListResponse(Schema):
    count: int
    next: str | None
    previous: str | None
    results: list[NoteSchema]
    meta: dict | None = None


class FileSchema(Schema):

    """An uploaded file (§4.12). ``FileUpload`` has no creation column, so ``created`` is null (§12)."""

    id: int
    title: str
    size: int
    created: datetime | None


class FileListResponse(Schema):
    count: int
    next: str | None
    previous: str | None
    results: list[FileSchema]
    meta: dict | None = None


class TagsResponse(Schema):
    tags: list[str]


class TagsBody(Schema):
    model_config = {"extra": "forbid"}

    tags: list[str]


# --- Shared helpers ---------------------------------------------------------------------------

def _resolve_parent(
    request: HttpRequest,
    get_parent_queryset: Callable[[HttpRequest], QuerySet],
    parent_label: str,
    parent_id: int,
) -> Model:
    """Resolve the parent through its authorized-view queryset; 404 unknown-or-unauthorized (§4.10)."""
    parent = get_parent_queryset(request).filter(pk=parent_id).first()
    if parent is None:
        msg = f"{parent_label} {parent_id} not found"
        raise not_found_problem(msg)
    return parent


def _require(request: HttpRequest, parent: Model, permission) -> None:
    """403 when the caller lacks ``permission`` on the (already-viewable) parent (I8)."""
    if not user_has_permission(request.user, parent, permission):
        raise PermissionDenied


def _serialize_note(note: Notes) -> dict:
    return {
        "id": note.pk,
        "entry": note.entry,
        "author": to_ref(note.author),
        "private": note.private,
        "edited": note.edited,
        "created": note.date,
        "updated": note.edit_time,
    }


def _serialize_file(file_obj: FileUpload) -> dict:
    # ``file.size`` is a storage stat (filesystem), not a DB query -- keeps list query counts flat.
    return {"id": file_obj.pk, "title": file_obj.title, "size": file_obj.file.size, "created": None}


def _read_tags(parent: Model) -> list[str]:
    return [tag.name for tag in parent.tags.all()]


def _write_tags(parent: Model, names: list[str]) -> None:
    """
    Replace the parent's tags with ``names`` via the v2 write path (assignment + ``save()``):
    tagulous normalises (``force_lowercase``) on save and the tag-inheritance signals fire exactly
    as they do for v2's ``remove_tags`` (``dojo/finding/api/views.py``). Assigning a *list* (not a
    rendered string) is safe for tags containing spaces/commas.
    """
    parent.tags = names
    parent.save()


# --- Factories --------------------------------------------------------------------------------

def build_notes_router(
    *,
    resource: str,
    parent_label: str,
    get_parent_queryset: Callable[[HttpRequest], QuerySet],
    view_permission="view",
    create_permission="view",
    on_note_created: Callable[..., None] | None = None,
    auth=NOT_SET,
) -> Router:
    """
    ``GET`` (paginated) + ``POST`` ``/{resource}/{id}/notes`` (§4.12).

    ``on_note_created(parent, note, *, user)`` -- optional resource-service callback fired after the
    new note is persisted and linked; it owns the resource's v2 note side-effects (JIRA comment sync,
    ``last_reviewed`` stamping, @mention notifications). The kernel imports none of that machinery.
    """
    router = Router(tags=[resource], auth=auth)
    notes_path = f"/{resource}/{{int:parent_id}}/notes"

    def list_notes(request: HttpRequest, parent_id: int):
        parent = _resolve_parent(request, get_parent_queryset, parent_label, parent_id)
        _require(request, parent, view_permission)
        # Mirror v2 exactly: return every note incl. private ones. In v2 the notes @action returns
        # `parent.notes.all()`; `private` only excludes a note from generated reports, it is not a
        # per-user read filter (§12). `select_related("author")` keeps the list query count flat.
        notes = parent.notes
        page_qs = notes.select_related("author").order_by("-date", "-id")
        envelope = paginate(request, count_qs=notes.all(), page_qs=page_qs, serialize=_serialize_note)
        return json_response(envelope)

    def create_note(request: HttpRequest, parent_id: int, payload: NoteCreate):
        parent = _resolve_parent(request, get_parent_queryset, parent_label, parent_id)
        _require(request, parent, create_permission)
        note = Notes(entry=payload.entry, author=request.user, private=payload.private)
        note.save()
        history = NoteHistory.objects.create(data=note.entry, time=note.date, current_editor=note.author)
        note.history.add(history)
        parent.notes.add(note)
        # Resource-specific side-effects (JIRA comment sync, last_reviewed stamping, @mention
        # notifications) live in the resource's service layer (I5/I6); the kernel imports none of
        # that machinery -- it only invokes the callback the factory was configured with, matching
        # v2's per-resource notes @action (dojo/<resource>/api/views.py).
        if on_note_created is not None:
            on_note_created(parent, note, user=request.user)
        return json_response(_serialize_note(note), status=201)

    list_notes.__name__ = f"list_{resource}_notes"
    create_note.__name__ = f"create_{resource}_note"
    router.get(notes_path, response=NoteListResponse, url_name=f"{resource}_notes_list")(list_notes)
    router.post(notes_path, response=NoteSchema, url_name=f"{resource}_notes_create")(create_note)
    return router


def build_files_router(
    *,
    resource: str,
    parent_label: str,
    get_parent_queryset: Callable[[HttpRequest], QuerySet],
    view_permission,
    add_permission,
    auth=NOT_SET,
) -> Router:
    """``GET`` list + ``POST`` (multipart) + ``GET .../{file_id}/download`` (§4.12)."""
    router = Router(tags=[resource], auth=auth)
    files_path = f"/{resource}/{{int:parent_id}}/files"
    download_path = f"/{resource}/{{int:parent_id}}/files/{{int:file_id}}/download"

    def list_files(request: HttpRequest, parent_id: int):
        parent = _resolve_parent(request, get_parent_queryset, parent_label, parent_id)
        _require(request, parent, view_permission)
        files = parent.files
        page_qs = files.all().order_by("id")
        envelope = paginate(request, count_qs=files.all(), page_qs=page_qs, serialize=_serialize_file)
        return json_response(envelope)

    def create_file(
        request: HttpRequest,
        parent_id: int,
        title: str = Form(...),
        file: UploadedFile = File(...),  # noqa: B008 -- ninja's declarative param default
    ):
        parent = _resolve_parent(request, get_parent_queryset, parent_label, parent_id)
        _require(request, parent, add_permission)
        # Mirror v2 FileSerializer: extension validation via FileUpload.clean() (settings
        # .FILE_UPLOAD_TYPES); v2 does NOT enforce a size cap. Title is globally unique on the
        # model, so pre-check it here (mirrors DRF's UniqueValidator -> 400, avoids a 500).
        upload = FileUpload(title=title, file=file)
        try:
            upload.clean()
        except DjangoValidationError as exc:
            raise validation_problem({"file": list(exc.messages)}) from exc
        if FileUpload.objects.filter(title=upload.title).exists():
            raise validation_problem({"title": ["A file with this title already exists."]})
        upload.save()
        parent.files.add(upload)
        return json_response(_serialize_file(upload), status=201)

    def download_file(request: HttpRequest, parent_id: int, file_id: int):
        parent = _resolve_parent(request, get_parent_queryset, parent_label, parent_id)
        _require(request, parent, view_permission)
        file_object = parent.files.filter(id=file_id).first()
        if file_object is None:
            msg = f"File {file_id} not associated with {parent_label} {parent_id}"
            raise not_found_problem(msg)
        # Streamed FileResponse with the correct content-type + Content-Disposition (mirrors v2's
        # download_file via generate_file_response). Ninja passes HttpResponse subclasses through.
        response = generate_file_response(file_object)
        response["X-API-Status"] = settings.API_V3_STATUS
        return response

    list_files.__name__ = f"list_{resource}_files"
    create_file.__name__ = f"create_{resource}_file"
    download_file.__name__ = f"download_{resource}_file"
    router.get(files_path, response=FileListResponse, url_name=f"{resource}_files_list")(list_files)
    router.post(files_path, response=FileSchema, url_name=f"{resource}_files_create")(create_file)
    router.get(download_path, url_name=f"{resource}_files_download")(download_file)
    return router


def build_tags_router(
    *,
    resource: str,
    parent_label: str,
    get_parent_queryset: Callable[[HttpRequest], QuerySet],
    view_permission="view",
    write_permission="edit",
    auth=NOT_SET,
) -> Router:
    """``GET`` + ``PUT`` (replace) + ``POST`` (append) ``/tags`` and ``DELETE /tags/{tag}`` (§4.12)."""
    router = Router(tags=[resource], auth=auth)
    tags_path = f"/{resource}/{{int:parent_id}}/tags"
    tag_item_path = f"/{resource}/{{int:parent_id}}/tags/{{tag}}"

    def get_tags(request: HttpRequest, parent_id: int):
        parent = _resolve_parent(request, get_parent_queryset, parent_label, parent_id)
        _require(request, parent, view_permission)
        return json_response({"tags": _read_tags(parent)})

    def replace_tags(request: HttpRequest, parent_id: int, payload: TagsBody):
        parent = _resolve_parent(request, get_parent_queryset, parent_label, parent_id)
        _require(request, parent, write_permission)
        _write_tags(parent, list(payload.tags))
        return json_response({"tags": _read_tags(parent)})

    def append_tags(request: HttpRequest, parent_id: int, payload: TagsBody):
        parent = _resolve_parent(request, get_parent_queryset, parent_label, parent_id)
        _require(request, parent, write_permission)
        # Case-insensitive dedup (stored tags are lowercased); order-preserving.
        merged = list(dict.fromkeys([*_read_tags(parent), *(t.lower() for t in payload.tags)]))
        _write_tags(parent, merged)
        return json_response({"tags": _read_tags(parent)})

    def delete_tag(request: HttpRequest, parent_id: int, tag: str):
        parent = _resolve_parent(request, get_parent_queryset, parent_label, parent_id)
        _require(request, parent, write_permission)
        current = _read_tags(parent)
        target = tag.lower()  # stored tags are force_lowercase; match case-insensitively (§12)
        if target not in current:
            msg = f"Tag '{tag}' not found on {parent_label} {parent_id}"
            raise not_found_problem(msg)
        _write_tags(parent, [name for name in current if name != target])
        response = HttpResponse(status=204)
        response["X-API-Status"] = settings.API_V3_STATUS
        return response

    get_tags.__name__ = f"get_{resource}_tags"
    replace_tags.__name__ = f"replace_{resource}_tags"
    append_tags.__name__ = f"append_{resource}_tags"
    delete_tag.__name__ = f"delete_{resource}_tag"
    router.get(tags_path, response=TagsResponse, url_name=f"{resource}_tags_list")(get_tags)
    router.put(tags_path, response=TagsResponse, url_name=f"{resource}_tags_replace")(replace_tags)
    router.post(tags_path, response=TagsResponse, url_name=f"{resource}_tags_append")(append_tags)
    router.delete(tag_item_path, url_name=f"{resource}_tags_delete")(delete_tag)
    return router
