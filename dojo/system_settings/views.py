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
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, StreamingHttpResponse, Http404, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from dojo.filters import ProductFilter, ProductFindingFilter
from dojo.forms import ProductForm, EngForm, DeleteProductForm
from dojo.models import System_Settings
from dojo.utils import (add_breadcrumb,
                        get_celery_worker_status)
from dojo.forms import SystemSettingsForm

logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_superuser)
def system_settings(request):
    try:
        system_settings_obj = System_Settings.objects.get()
    except:
        system_settings_obj = System_Settings()
    celery_status = get_celery_worker_status()
    celery_bool = True
    celery_stat = celery_status.keys()[0]
    celery_msg = celery_status.values()[0]
    if celery_status.keys()[0] == 'ERROR':
        celery_bool = False
    """
    **** To be Finished JIRA Status info ****
    jira_bool = True
    jira_msg = 'None'
    if not celery_bool:
        jira_bool = False
        jira_msg = 'Celery is not working properly'
    else:

        try:
            jira_server = jform.cleaned_data.get('url').rstrip('/')
            jira = JIRA(server=jform.cleaned_data.get('url').rstrip('/'),
                        basic_auth=(jform.cleaned_data.get('username'), jform.cleaned_data.get('password')))
            new_j = jform.save(commit=False)
            new_j.url = jira_server
            new_j.save()
            messages.add_message(request,
                                 messages.SUCCESS,

                                 'JIRA Configuration Successfully Created.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('jira', ))
        except:
            messages.add_message(request,
                                 messages.ERROR,
                                 'Unable to authenticate. Please check the URL, username, and password.',
                                 extra_tags='alert-danger')

    """
    form = SystemSettingsForm(instance=system_settings_obj)
    if request.method == 'POST':
        form = SystemSettingsForm(request.POST, instance=system_settings_obj)
        if form.is_valid():
            new_settings = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Settings saved.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('system_settings', ))
    add_breadcrumb(title="Application settings", top_level=False, request=request)
    return render(request, 'dojo/system_settings.html',
                  {'form': form,
                   'celery_bool': celery_bool,
                   'celery_msg': celery_msg,
                   'celery_status': celery_stat})
