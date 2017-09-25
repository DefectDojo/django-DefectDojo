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
from dojo.utils import get_page_items, add_breadcrumb, get_punchcard_data, handle_uploaded_selenium, get_system_setting
from dojo.forms import SystemSettingsForm

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_superuser)
def system_settings(request):
    try:
        system_settings_obj = System_Settings.objects.get()
    except:
        system_settings_obj = System_Settings()
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
                  {'form': form})
