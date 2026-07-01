import logging
import re

from django.contrib import messages
from django.db import transaction
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_POST

from dojo.announcement.models import Announcement, UserAnnouncement
from dojo.announcement.os_message import OS_MESSAGE_DISMISSED_KEY
from dojo.announcement.ui.forms import AnnouncementCreateForm, AnnouncementRemoveForm
from dojo.user.models import UserContactInfo
from dojo.utils import add_breadcrumb

logger = logging.getLogger(__name__)


def configure_announcement(request):
    remove = False
    if request.method == "GET":
        try:
            announcement = Announcement.objects.get(id=1)
            form = AnnouncementRemoveForm(
                initial={
                    "message": announcement.message,
                    "style": announcement.style,
                    "dismissable": announcement.dismissable,
                },
            )
            remove = True
        except Announcement.DoesNotExist:
            form = AnnouncementCreateForm()
    elif request.method == "POST":
        if "_Remove" in request.POST:
            Announcement.objects.all().delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                _("Announcement removed for everyone."),
                extra_tags="alert-success",
            )
            return HttpResponseRedirect("dashboard")
        form = AnnouncementCreateForm(request.POST)
        announcement, created = Announcement.objects.get_or_create(id=1)
        if form.is_valid() and created:
            announcement.message = form.cleaned_data["message"]
            announcement.style = form.cleaned_data["style"]
            announcement.dismissable = form.cleaned_data["dismissable"]
            announcement.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                _("Announcement updated successfully."),
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("configure_announcement"))

    add_breadcrumb(
        title=gettext("Announcement Configuration"),
        top_level=True,
        request=request,
    )
    return render(
        request, "dojo/announcement.html", {"form": form, "remove": remove},
    )


def dismiss_announcement(request):
    if request.method == "POST":
        deleted_count, _objects_deleted = UserAnnouncement.objects.filter(
            user=request.user, announcement=1,
        ).delete()
        if deleted_count > 0:
            messages.add_message(
                request,
                messages.SUCCESS,
                _("Announcement removed."),
                extra_tags="alert-success",
            )
            return HttpResponseRedirect("dashboard")
        messages.add_message(
            request,
            messages.ERROR,
            _("Failed to remove announcement."),
            extra_tags="alert-danger",
        )
        return render(request, "dojo/dismiss_announcement.html")
    return render(request, "dojo/dismiss_announcement.html")


@require_POST
def dismiss_os_message(request):
    if not request.user.is_authenticated:
        return HttpResponseForbidden()
    token = request.POST.get("token", "").strip()
    if token and re.fullmatch(r"[0-9a-f]{1,64}", token):
        # user_state_details is a shared JSON blob for many per-user flags, so
        # read-modify-write it under a row lock to avoid clobbering a concurrent
        # write to a different key (lost update).
        with transaction.atomic():
            contact, _ = UserContactInfo.objects.get_or_create(user=request.user)
            contact = UserContactInfo.objects.select_for_update().get(pk=contact.pk)
            state = contact.user_state_details or {}
            if state.get(OS_MESSAGE_DISMISSED_KEY) != token:
                state[OS_MESSAGE_DISMISSED_KEY] = token
                contact.user_state_details = state
                contact.save(update_fields=["user_state_details"])
    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        return HttpResponse(status=204)
    referer = request.META.get("HTTP_REFERER")
    if referer and url_has_allowed_host_and_scheme(
        referer, allowed_hosts={request.get_host()}, require_https=request.is_secure(),
    ):
        return HttpResponseRedirect(referer)
    return HttpResponseRedirect("/")
