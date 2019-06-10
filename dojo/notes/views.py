# Standard library imports
import logging

# Third party imports
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.core.exceptions import PermissionDenied


# Local application/library imports
from dojo.forms import DeleteNoteForm
from dojo.models import Notes, Test, Finding

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

    if page is None or str(request.user) != note.author.username:
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
