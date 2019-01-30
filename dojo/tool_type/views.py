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
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from dojo.filters import ProductFilter, ProductFindingFilter
from dojo.forms import ProductForm, EngForm, DeleteProductForm
from dojo.models import Product_Type, Finding, Product, Engagement, ScanSettings, Risk_Acceptance
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
def new_tool_type(request):
    if request.method == 'POST':
        tform = ToolTypeForm(request.POST, instance=Tool_Type())
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Tool Type Configuration Successfully Created.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('tool_type', ))
    else:
        tform = ToolTypeForm()
        add_breadcrumb(title="New Tool Type Configuration", top_level=False, request=request)
    return render(request, 'dojo/new_tool_type.html',
                  {'tform': tform})

@user_passes_test(lambda u: u.is_staff)
def edit_tool_type(request, ttid):
    tool_type = Tool_Type.objects.get(pk=ttid)
    if request.method == 'POST':
        tform = ToolTypeForm(request.POST, instance=tool_type)
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Tool Type Configuration Successfully Updated.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('tool_type', ))
    else:
        tform = ToolTypeForm(instance=tool_type)
    add_breadcrumb(title="Edit Tool Type Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/edit_tool_type.html',
                  {
                      'tform': tform,
                  })

@user_passes_test(lambda u: u.is_staff)
def delete_issue(request, find):
    j_issue = JIRA_Issue.objects.get(finding=find)
    jira = JIRA(server=Tool_Type.url, basic_auth=(Tool_Type.username, Tool_Type.password))
    issue = jira.issue(j_issue.jira_id)
    issue.delete()

@user_passes_test(lambda u: u.is_staff)
def tool_type(request):
    confs = Tool_Type.objects.all().order_by('name')
    add_breadcrumb(title="Tool Type List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/tool_type.html',
                  {'confs': confs,
                   })
