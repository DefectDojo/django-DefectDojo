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
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from dojo.filters import ProductFilter, ProductFindingFilter
from dojo.forms import ProductForm, EngForm, DeleteProductForm
from dojo.models import Product_Type, Finding, Product, Engagement, ScanSettings, Risk_Acceptance
from dojo.utils import dojo_crypto_encrypt, prepare_for_view, FileIterWrapper
from dojo.utils import get_page_items, add_breadcrumb, get_punchcard_data, get_system_setting
from dojo.models import *
from dojo.models import *
from dojo.forms import *
from jira import JIRA
from dojo.tasks import *
from dojo.forms import *
from dojo.product import views as ds

logger = logging.getLogger(__name__)

@user_passes_test(lambda u: u.is_staff)
def new_tool_config(request):
    if request.method == 'POST':
        tform = ToolConfigForm(request.POST)
        if tform.is_valid():
            #form.tool_type = tool_type
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Tool Configuration Successfully Created.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('tool_config', ))
    else:
        tform = ToolConfigForm()
        add_breadcrumb(title="New Tool Configuration", top_level=False, request=request)
    return render(request, 'dojo/new_tool_config.html',
                  {'tform': tform})

@user_passes_test(lambda u: u.is_staff)
def edit_tool_config(request, ttid):
    tool_config = Tool_Configuration.objects.get(pk=ttid)
    if request.method == 'POST':
        tform = ToolConfigForm(request.POST, instance=tool_config)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            form_copy.password = dojo_crypto_encrypt(tform.cleaned_data['password'])
            print "######"
            print tform.cleaned_data['ssh']

            form_copy.ssh = dojo_crypto_encrypt(tform.cleaned_data['ssh'])
            form_copy.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Tool Configuration Successfully Updated.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('tool_config', ))
    else:
        tool_config.password = prepare_for_view(tool_config.password)
        tool_config.ssh = prepare_for_view(tool_config.ssh)
        tform = ToolConfigForm(instance=tool_config)
    add_breadcrumb(title="Edit Tool Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/edit_tool_config.html',
                  {
                      'tform': tform,
                  })

@user_passes_test(lambda u: u.is_staff)
def delete_issue(request, find):
    j_issue = JIRA_Issue.objects.get(finding=find)
    jira = JIRA(server=Tool_config.url, basic_auth=(Tool_config.username, Tool_config.password))
    issue = jira.issue(j_issue.jira_id)
    issue.delete()

@user_passes_test(lambda u: u.is_staff)
def tool_config(request):
    confs = Tool_Configuration.objects.all().order_by('name')
    add_breadcrumb(title="Tool Configuration List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/tool_config.html',
                  {'confs': confs,
                   })
