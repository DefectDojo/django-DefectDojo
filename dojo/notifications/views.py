# #  product
import logging
import sys
import json
import pprint
from datetime import datetime
from math import ceil

from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.http import HttpResponseRedirect, StreamingHttpResponse, Http404, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt

from dojo.filters import ProductFilter, ProductFindingFilter
from dojo.forms import ProductForm, EngForm, DeleteProductForm
from dojo.models import Notifications, Dojo_User
from dojo.utils import get_page_items, add_breadcrumb, get_punchcard_data, handle_uploaded_selenium, get_system_setting
from dojo.forms import NotificationsForm
from pprint import pprint

logger = logging.getLogger(__name__)


def personal_notifications(request):
    try:
        notifications_obj = Notifications.objects.get(user=request.user)
    except:
        notifications_obj = Notifications(user=request.user)

    form = NotificationsForm(instance=notifications_obj)
    if request.method == 'POST':
        form = NotificationsForm(request.POST, instance=notifications_obj)
        if form.is_valid():
            new_settings = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Settings saved.',
                                 extra_tags='alert-success')

    add_breadcrumb(title="Personal notification settings", top_level=False, request=request)
    return render(request, 'dojo/notifications.html',
                  {'form': form,
                   'scope': 'personal',
                   'admin': request.user.is_superuser})


@user_passes_test(lambda u: u.is_superuser)
def global_notifications(request):
    try:
        notifications_obj = Notifications.objects.get(user=None)
    except:
        notifications_obj = Notifications(user=None)

    form = NotificationsForm(instance=notifications_obj)
    if request.method == 'POST':
        form = NotificationsForm(request.POST, instance=notifications_obj)
        if form.is_valid():
            new_settings = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Settings saved.',
                                 extra_tags='alert-success')

    add_breadcrumb(title="Global notification settings", top_level=False, request=request)
    return render(request, 'dojo/notifications.html',
                  {'form': form,
                   'scope': 'global',
                   'admin': request.user.is_superuser})

