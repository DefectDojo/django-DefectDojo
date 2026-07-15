import logging
from contextlib import suppress
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse

from dojo.authorization.authorization import user_has_permission, user_has_permission_or_403
from dojo.authorization.roles_permissions import Permissions
from dojo.forms import AddOnlyManageFileFormSet, ManageFileFormSet
from dojo.models import (
    Engagement,
    FileUpload,
    Finding,
    Test,
)
from dojo.product_announcements import ErrorPageProductAnnouncement
from dojo.utils import generate_file_response

logger = logging.getLogger(__name__)


def custom_error_view(request, exception=None):
    ErrorPageProductAnnouncement(request=request)
    return render(request, "500.html", {}, status=500)


def custom_unauthorized_view(request, exception=None):
    ErrorPageProductAnnouncement(request=request)
    return render(request, "403.html", {}, status=400)


def custom_bad_request_view(request, exception=None):
    ErrorPageProductAnnouncement(request=request)
    return render(request, "400.html", {}, status=400)


def manage_files(request, oid, obj_type):
    if obj_type == "Engagement":
        obj = get_object_or_404(Engagement, pk=oid)
        obj_vars = ("view_engagement", "engagement_set")
    elif obj_type == "Test":
        obj = get_object_or_404(Test, pk=oid)
        obj_vars = ("view_test", "test_set")
    elif obj_type == "Finding":
        obj = get_object_or_404(Finding, pk=oid)
        obj_vars = ("view_finding", "finding_set")
    else:
        raise Http404

    has_file_add_permission = user_has_permission(request.user, obj, Permissions.Product_Tracking_Files_Add)
    has_file_edit_permission = user_has_permission(request.user, obj, Permissions.Product_Tracking_Files_Edit)
    if not (has_file_add_permission or has_file_edit_permission):
        raise PermissionDenied

    formset_class = ManageFileFormSet if has_file_edit_permission else AddOnlyManageFileFormSet
    files_queryset = obj.files.all() if has_file_edit_permission else FileUpload.objects.none()
    files_formset = formset_class(queryset=files_queryset)
    error = False

    if request.method == "POST":
        files_formset = formset_class(
            request.POST, request.FILES, queryset=files_queryset)
        if files_formset.is_valid():
            # remove all from database and disk

            files_formset.save()

            for o in getattr(files_formset, "deleted_objects", []):
                if has_file_edit_permission:
                    logger.debug("removing file: %s", o.file.name)
                    with suppress(FileNotFoundError):
                        (Path(settings.MEDIA_ROOT) / o.file.name).unlink()

            for o in files_formset.new_objects:
                logger.debug("adding file: %s", o.file.name)
                obj.files.add(o)

            orphan_files = FileUpload.objects.filter(engagement__isnull=True,
                                                     test__isnull=True,
                                                     finding__isnull=True)
            for o in orphan_files:
                logger.debug("purging orphan file: %s", o.file.name)
                with suppress(FileNotFoundError):
                    (Path(settings.MEDIA_ROOT) / o.file.name).unlink()
                o.delete()

            messages.add_message(
                request,
                messages.SUCCESS,
                "Files updated successfully.",
                extra_tags="alert-success")

        else:
            error = True
            messages.add_message(
                request,
                messages.ERROR,
                "Please check form data and try again.",
                extra_tags="alert-danger")

        if not error:
            return HttpResponseRedirect(reverse(obj_vars[0], args=(oid, )))
    return render(
        request, "dojo/manage_files.html", {
            "files_formset": files_formset,
            "obj": obj,
            "obj_type": obj_type,
        })


@login_required
def protected_serve(request, path, document_root=None, *, show_indexes=False):
    """Serve the file only after verifying the user is supposed to see the file."""
    file = get_object_or_404(FileUpload, file=path)
    object_set = list(file.engagement_set.all()) + list(file.test_set.all()) + list(file.finding_set.all())
    # Determine if there is an object to query permission checks from
    if len(object_set) == 0:
        raise Http404
    # Should only one item (but not sure what type) in the list, so O(n=1)
    for obj in object_set:
        if isinstance(obj, (Engagement, Test, Finding)):
            user_has_permission_or_403(request.user, obj, "view")

    return generate_file_response(file)


def access_file(request, fid, oid, obj_type, *, url=False):
    def check_file_belongs_to_object(file, object_manager, object_id):
        if not object_manager.filter(id=object_id).exists():
            raise PermissionDenied

    file = get_object_or_404(FileUpload, pk=fid)
    if obj_type == "Engagement":
        obj = get_object_or_404(Engagement, pk=oid)
        user_has_permission_or_403(request.user, obj, "view")
        obj_manager = file.engagement_set
    elif obj_type == "Test":
        obj = get_object_or_404(Test, pk=oid)
        user_has_permission_or_403(request.user, obj, "view")
        obj_manager = file.test_set
    elif obj_type == "Finding":
        obj = get_object_or_404(Finding, pk=oid)
        user_has_permission_or_403(request.user, obj, "view")
        obj_manager = file.finding_set
    else:
        raise Http404
    check_file_belongs_to_object(file, obj_manager, obj.id)

    return generate_file_response(file)
