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
from django.utils import timezone

from dojo.filters import ProductFilter, ProductFindingFilter
from dojo.forms import ProductForm, EngForm, DeleteToolProductSettingsForm
from dojo.models import Product_Type, Finding, Product, Engagement, ScanSettings, Risk_Acceptance
from dojo.utils import get_page_items, add_breadcrumb, get_punchcard_data, get_system_setting
from dojo.models import *
from dojo.models import *
from dojo.forms import *
from jira import JIRA
from dojo.tasks import *
from dojo.forms import *
from dojo.product import views as ds

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)

@user_passes_test(lambda u: u.is_staff)
def new_tool_product(request, pid):
    prod = get_object_or_404(Product, id=pid)
    if request.method == 'POST':
        tform = ToolProductSettingsForm(request.POST)
        if tform.is_valid():
            #form.tool_type = tool_type
            new_prod = tform.save(commit=False)
            new_prod.product = prod
            new_prod.save()

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product Tool Configuration Successfully Created.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    else:
        tform = ToolProductSettingsForm()
        add_breadcrumb(title="New Product Tool Configuration", top_level=False, request=request)
    return render(request, 'dojo/new_tool_product.html',
                  {'tform': tform,
                  'pid': pid})

@user_passes_test(lambda u: u.is_staff)
def view_tool_product(request, pid, ttid):
    tool = Tool_Product_Settings.objects.get(pk=ttid)
    notes = tool.notes.all()

    if request.method == 'POST':
        form = NoteForm(request.POST)
        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            tool.notes.add(new_note)
            form = NoteForm()
            #url = request.build_absolute_uri(reverse("view_test", args=(test.id,)))
            #title="Test: %s on %s" % (test.test_type.name, test.engagement.product.name)
            #process_notifications(request, new_note, url, title)
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Note added successfully.',
                                 extra_tags='alert-success')
    else:
        form = NoteForm()

    add_breadcrumb(title="View Product Tool Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/view_tool_product.html',
                  {
                      'tool': tool,
                      'notes': notes,
                      'form': form
                  })

@user_passes_test(lambda u: u.is_staff)
def edit_tool_product(request, pid, ttid):
    tool_product = Tool_Product_Settings.objects.get(pk=ttid)

    if request.method == 'POST':
        tform = ToolProductSettingsForm(request.POST, instance=tool_product)
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Tool Product Configuration Successfully Updated.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    else:
        tform = ToolProductSettingsForm(instance=tool_product)

    add_breadcrumb(title="Edit Product Tool Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/edit_tool_product.html',
                  {
                      'tform': tform,
                  })

@user_passes_test(lambda u: u.is_staff)
def delete_tool_product(request, pid, ttid):
    tool_product = Tool_Product_Settings.objects.get(pk=ttid)

    if request.method == 'POST':
        tform = DeleteToolProductSettingsForm(request.POST, instance=tool_product)
        tool_product.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             'Tool Product Successfully Deleted.',
                             extra_tags='alert-success')
        return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    else:
        tform = ToolProductSettingsForm(instance=tool_product)

    add_breadcrumb(title="Delete Product Tool Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/delete_tool_product.html',
                  {
                      'tform': tform,
                  })

@user_passes_test(lambda u: u.is_staff)
def tool_product(request):
    confs = Tool_Product_Settings.objects.all().order_by('name')
    add_breadcrumb(title="Tool Configuration List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/tool_product.html',
                  {'confs': confs,
                   })
