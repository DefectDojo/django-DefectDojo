import logging

from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext
from django.utils.translation import gettext_lazy as _

from dojo.authorization.authorization_decorators import (
    user_is_configuration_authorized,
)
from dojo.forms import AnnouncementCreateForm, AnnouncementRemoveForm
from dojo.models import Announcement, UserAnnouncement
from dojo.utils import add_breadcrumb

logger = logging.getLogger(__name__)


@user_is_configuration_authorized("dojo.change_announcement")
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
