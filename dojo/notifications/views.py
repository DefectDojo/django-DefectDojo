# #  product
import logging

from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import render
from django.utils.translation import gettext as _

from dojo.models import Notifications
from dojo.utils import get_enabled_notifications_list
from dojo.utils import add_breadcrumb
from dojo.forms import NotificationsForm

logger = logging.getLogger(__name__)


def render_page(request, form, scope: str):
    return render(request, 'dojo/notifications.html',
                  {'form': form,
                   'scope': scope,
                   'enabled_notifications': get_enabled_notifications_list(),
                   'admin': request.user.is_superuser
                   })


def personal_notifications(request):
    try:
        notifications_obj = Notifications.objects.get(user=request.user, product__isnull=True)
    except:
        notifications_obj = Notifications(user=request.user)

    form = NotificationsForm(instance=notifications_obj)

    if request.method == 'POST':
        form = NotificationsForm(request.POST, instance=notifications_obj)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Settings saved.'),
                                 extra_tags='alert-success')

    add_breadcrumb(title=_("Personal notification settings"), top_level=False, request=request)

    return render_page(request, form, 'personal')


@user_passes_test(lambda u: u.is_superuser)
def system_notifications(request):
    try:
        notifications_obj = Notifications.objects.get(user=None, product__isnull=True, template=False)
    except:
        notifications_obj = Notifications(user=None, template=False)

    form = NotificationsForm(instance=notifications_obj)
    if request.method == 'POST':
        form = NotificationsForm(request.POST, instance=notifications_obj)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Settings saved.'),
                                 extra_tags='alert-success')

    add_breadcrumb(title=_("System notification settings"), top_level=False, request=request)

    return render_page(request, form, 'system')


@user_passes_test(lambda u: u.is_superuser)
def template_notifications(request):
    try:
        notifications_obj = Notifications.objects.get(template=True)
    except:
        notifications_obj = Notifications(user=None, template=True)

    form = NotificationsForm(instance=notifications_obj)
    if request.method == 'POST':
        form = NotificationsForm(request.POST, instance=notifications_obj)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Settings saved.'),
                                 extra_tags='alert-success')

    add_breadcrumb(title=_("Template notification settings"), top_level=False, request=request)

    return render_page(request, form, 'template')
