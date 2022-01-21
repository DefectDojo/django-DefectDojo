import logging

from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from django.urls import reverse
from django.http import HttpResponseRedirect
from dojo.utils import add_breadcrumb

from dojo.forms import AnnouncementBannerForm
from dojo.models import AnnouncementBanner
from dojo.authorization.authorization_decorators import user_is_configuration_authorized

logger = logging.getLogger(__name__)


@user_is_configuration_authorized('dojo.change_announcementbanner', 'superuser')
def configure_announcement_banner(request):
    try:
        announcement_banner, created = AnnouncementBanner.objects.get_or_create(id=1)
        if created:
            logger.info('Announcement Banner with ID=1 did not exist, was created')
        if request.method == 'POST':
            form = AnnouncementBannerForm(request.POST)
            if form.is_valid():
                announcement_banner.message = form.cleaned_data['message']
                announcement_banner.style = form.cleaned_data['style']
                announcement_banner.dismissable = form.cleaned_data['dismissable']
                announcement_banner.enable = form.cleaned_data['enable']
                announcement_banner.save()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    'Announcement banner updated successfully.',
                    extra_tags="alert-success",
                )
                return HttpResponseRedirect(reverse("configure_announcement_banner"))
        else:
            form = AnnouncementBannerForm(initial={
                'message': announcement_banner.message,
                'style': announcement_banner.style,
                'dismissable': announcement_banner.dismissable,
                'enable': announcement_banner.enable
            })

        add_breadcrumb(title="Announcement Banner Configuration", top_level=True, request=request)
        return render(request, 'dojo/announcement_banner.html', {
                'form': form,
                'message': announcement_banner.message,
                'style': announcement_banner.style,
                'dismissable': announcement_banner.dismissable
        })
    except AnnouncementBanner.MultipleObjectsReturned:
        logger.error('Multiple AnnouncementBanner objects returned')

