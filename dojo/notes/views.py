# Standard library imports
import logging
from typing import Literal, get_args

# Third party imports
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _

from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.roles_permissions import Permissions
from dojo.cred.queries import get_authorized_cred_mappings
from dojo.engagement.queries import get_authorized_engagements
from dojo.finding.queries import get_authorized_findings

# Local application/library imports
from dojo.forms import DeleteNoteForm, NoteForm, TypedNoteForm
from dojo.models import Cred_User, Engagement, Finding, Note_Type, NoteHistory, Notes, Test
from dojo.test.queries import get_authorized_tests

logger = logging.getLogger(__name__)

SUPPORTED_PAGES = Literal["engagement", "test", "finding", "cred"]


def _get_page_details(request: HttpRequest, note_id: int, page: SUPPORTED_PAGES | None, objid: int) -> tuple[Notes, Engagement | Test | Finding | Cred_User, int, str]:
    note = get_object_or_404(Notes, id=note_id)
    # Quick check to make sure we have a valid page
    if page is None or page not in get_args(SUPPORTED_PAGES):
        raise PermissionDenied
    # Get the real object based on page type
    if page == "engagement":
        obj = get_authorized_engagements(Permissions.Engagement_View).filter(id=objid).first()
        reverse_url = "view_engagement"
    elif page == "test":
        obj = get_authorized_tests(Permissions.Test_View).filter(id=objid).first()
        reverse_url = "view_test"
    elif page == "finding":
        obj = get_authorized_findings(Permissions.Finding_View).filter(id=objid).first()
        reverse_url = "view_finding"
    elif page == "cred":
        obj = get_authorized_cred_mappings(Permissions.Cred_View).filter(id=objid).first()
        reverse_url = "view_cred_details"
    else:
        # If we get here, something is wrong, so let's just raise PermissionDenied
        raise PermissionDenied
    # Ensure we have an object back, and if not, raise the 404 like before
    if obj is None:
        raise Http404
    # Next check if the note supplied is even attached to the object
    if obj.notes.filter(id=note.id).exists() is False:
        raise PermissionDenied

    return note, obj, obj.id, reverse_url


def delete_note(request: HttpRequest, note_id: int, page: SUPPORTED_PAGES, objid: int) -> HttpResponseRedirect:
    note, obj, object_id, reverse_url = _get_page_details(request, note_id, page, objid)
    form = DeleteNoteForm(request.POST, instance=note)

    if str(request.user) != note.author.username:
        user_has_permission_or_403(request.user, obj, Permissions.Note_Delete)

    if form.is_valid():
        note.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             _("Note deleted."),
                             extra_tags="alert-success")
    else:
        messages.add_message(request,
                             messages.SUCCESS,
                             _("Note was not successfully deleted."),
                             extra_tags="alert-danger")

    return HttpResponseRedirect(reverse(reverse_url, args=(object_id, )))


def edit_note(request: HttpRequest, note_id: int, page: SUPPORTED_PAGES, objid: int) -> HttpResponseRedirect:
    note, obj, object_id, reverse_url = _get_page_details(request, note_id, page, objid)

    if str(request.user) != note.author.username:
        user_has_permission_or_403(request.user, obj, Permissions.Note_Edit)

    note_type_activation = Note_Type.objects.filter(is_active=True).count()
    if note_type_activation:
        available_note_types = find_available_notetypes(obj, note)

    if request.method == "POST":
        if note_type_activation:
            form = TypedNoteForm(request.POST, available_note_types=available_note_types, instance=note)
        else:
            form = NoteForm(request.POST, instance=note)
        if form.is_valid():
            note = form.save(commit=False)
            note.edited = True
            note.editor = request.user
            note.edit_time = timezone.now()
            if note_type_activation:
                history = NoteHistory(note_type=note.note_type,
                                      data=note.entry,
                                      time=note.edit_time,
                                      current_editor=note.editor)
            else:
                history = NoteHistory(data=note.entry,
                                      time=note.edit_time,
                                      current_editor=note.editor)
            history.save()
            note.history.add(history)
            note.save()
            obj.last_reviewed = note.date
            obj.last_reviewed_by = request.user
            obj.save()
            form = NoteForm()
            messages.add_message(request,
                                messages.SUCCESS,
                                _("Note edited."),
                                extra_tags="alert-success")
            return HttpResponseRedirect(reverse(reverse_url, args=(object_id, )))
        messages.add_message(request,
                            messages.SUCCESS,
                            _("Note was not succesfully edited."),
                            extra_tags="alert-danger")
    elif note_type_activation:
        form = TypedNoteForm(available_note_types=available_note_types, instance=note)
    else:
        form = NoteForm(instance=note)

    return render(
        request, "dojo/edit_note.html", {
            "note": note,
            "form": form,
            "page": page,
            "objid": objid,
        })


def note_history(request: HttpRequest, note_id: int, page: SUPPORTED_PAGES, objid: int) -> HttpResponseRedirect:
    note, obj, object_id, reverse_url = _get_page_details(request, note_id, page, objid)

    if str(request.user) != note.author.username:
        user_has_permission_or_403(request.user, obj, Permissions.Note_View_History)

    history = note.history.all()

    if request.method == "POST":
        return HttpResponseRedirect(reverse(reverse_url, args=(object_id, )))

    return render(
        request, "dojo/view_note_history.html", {
            "history": history,
            "note": note,
            "page": page,
            "objid": objid,
        })


def find_available_notetypes(finding, editing_note):
    notes = finding.notes.all()
    single_note_types = Note_Type.objects.filter(is_single=True, is_active=True).values_list("id", flat=True)
    multiple_note_types = Note_Type.objects.filter(is_single=False, is_active=True).values_list("id", flat=True)
    available_note_types = []
    for note_type_id in multiple_note_types:
        available_note_types.append(note_type_id)
    for note_type_id in single_note_types:
        for note in notes:
            if note_type_id == note.note_type_id:
                break
        else:
            available_note_types.append(note_type_id)
    available_note_types.append(editing_note.note_type_id)
    available_note_types = list(set(available_note_types))
    return Note_Type.objects.filter(id__in=available_note_types).order_by("-id")
