# Standard library imports
import logging

# Third party imports
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.core.exceptions import PermissionDenied
from django.utils import timezone


# Local application/library imports
from dojo.forms import DeleteNoteForm, NoteForm
from dojo.models import Notes, Test, Finding, NoteHistory

logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_staff)
def delete_issue(request, id, page, objid):
    note = get_object_or_404(Notes, id=id)
    reverse_url = None
    object_id = None
    if page == "test":
        object = get_object_or_404(Test, id=objid)
        object_id = object.id
        reverse_url = "view_test"
    elif page == "finding":
        object = get_object_or_404(Finding, id=objid)
        object_id = object.id
        reverse_url = "view_finding"
    form = DeleteNoteForm(request.POST, instance=note)

    if page is None or str(request.user) != note.author.username and not request.user.is_superuser:
        raise PermissionDenied

    if form.is_valid():
        note.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             'Note deleted.',
                             extra_tags='alert-success')
    else:
        messages.add_message(request,
                             messages.SUCCESS,
                             'Note was not succesfully deleted.',
                             extra_tags='alert-danger')

    return HttpResponseRedirect(reverse(reverse_url, args=(object_id, )))


@user_passes_test(lambda u: u.is_staff)
def edit_issue(request, id, page, objid):
    note = get_object_or_404(Notes, id=id)
    reverse_url = None
    object_id = None

    if page is None or str(request.user) != note.author.username and not request.user.is_superuser:
        raise PermissionDenied

    if page == "test":
        object = get_object_or_404(Test, id=objid)
        object_id = object.id
        reverse_url = "view_test"
    elif page == "finding":
        object = get_object_or_404(Finding, id=objid)
        object_id = object.id
        reverse_url = "view_finding"

    if request.method == 'POST':
        form = NoteForm(request.POST, instance=note)
        if form.is_valid():
            note = form.save(commit=False)
            note.edited = True
            note.editor = request.user
            note.edit_time = timezone.now()
            history = NoteHistory(data=note.entry,
                                    time=note.edit_time,
                                    current_editor=note.editor)
            history.save()
            note.history.add(history)
            note.save()
            object.last_reviewed = note.date
            object.last_reviewed_by = request.user
            object.save()
            form = NoteForm()
            messages.add_message(request,
                                messages.SUCCESS,
                                'Note edited.',
                                extra_tags='alert-success')
            return HttpResponseRedirect(reverse(reverse_url, args=(object_id, )))
        else:
            messages.add_message(request,
                                messages.SUCCESS,
                                'Note was not succesfully edited.',
                                extra_tags='alert-danger')
    else:
        form = NoteForm(instance=note)

    return render(
        request, 'dojo/edit_note.html', {
            'note': note,
            'form': form,
            'page': page,
            'objid': objid,
        })


@user_passes_test(lambda u: u.is_staff)
def note_history(request, id, page, objid):
    note = get_object_or_404(Notes, id=id)
    reverse_url = None
    object_id = None

    if page == "test":
        object = get_object_or_404(Test, id=objid)
        object_id = object.id
        reverse_url = "view_test"
    elif page == "finding":
        object = get_object_or_404(Finding, id=objid)
        object_id = object.id
        reverse_url = "view_finding"

    history = note.history.all()

    if request.method == 'POST':
        return HttpResponseRedirect(reverse(reverse_url, args=(object_id, )))

    return render(
        request, 'dojo/view_note_history.html', {
            'history': history,
            'note': note,
            'page': page,
            'objid': objid,
        })
