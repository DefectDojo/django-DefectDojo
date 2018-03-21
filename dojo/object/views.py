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
from dojo.utils import get_page_items, add_breadcrumb, get_punchcard_data, get_system_setting
from dojo.models import *
from dojo.forms import *
from dojo.product import views as ds
from tagging.utils import get_tag_list
from tagging.views import TaggedItem

logger = logging.getLogger(__name__)

@user_passes_test(lambda u: u.is_staff)
def new_object(request, pid):
    prod = get_object_or_404(Product, id=pid)
    if request.method == 'POST':
        tform = ObjectSettingsForm(request.POST)
        if tform.is_valid():
            new_prod = tform.save(commit=False)
            new_prod.product = prod
            new_prod.save()

            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            new_prod.tags = t

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Added Tracked File to a Product',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_objects', args=(pid,)))
    else:
        tform = ObjectSettingsForm()
        add_breadcrumb(title="Add Tracked Files to a Product", top_level=False, request=request)

    return render(request, 'dojo/new_object.html',
                  {'tform': tform,
                  'pid': prod.id})

@user_passes_test(lambda u: u.is_staff)
def view_objects(request, pid):
    object_queryset = Objects.objects.filter(product=pid).order_by('path', 'folder', 'artifact')

    add_breadcrumb(title="Tracked Product Files, Paths and Artifacts", top_level=False, request=request)

    return render(request,
                  'dojo/view_objects.html',
                  {
                      'object_queryset': object_queryset,
                      'pid': pid
                  })

@user_passes_test(lambda u: u.is_staff)
def edit_object(request, pid, ttid):
    object = Objects.objects.get(pk=ttid)

    if request.method == 'POST':
        tform = ObjectSettingsForm(request.POST, instance=object)
        if tform.is_valid():
            tform.save()

            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            object.tags = t

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Tool Product Configuration Successfully Updated.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_objects', args=(pid,)))
    else:
        tform = ObjectSettingsForm(instance=object,
        initial={'tags': get_tag_list(Tag.objects.get_for_object(object))})

    tform.initial['tags'] = [tag.name for tag in object.tags]
    add_breadcrumb(title="Edit Tracked Files", top_level=False, request=request)
    return render(request,
                  'dojo/edit_object.html',
                  {
                      'tform': tform,
                  })

@user_passes_test(lambda u: u.is_staff)
def delete_object(request, pid, ttid):
    object = Objects.objects.get(pk=ttid)

    if request.method == 'POST':
        tform = ObjectSettingsForm(request.POST, instance=object)
        object.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             'Tracked Product Files Deleted.',
                             extra_tags='alert-success')
        return HttpResponseRedirect(reverse('view_objects', args=(pid,)))
    else:
        tform = DeleteObjectsSettingsForm(instance=object)

    add_breadcrumb(title="Delete Product Tool Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/delete_object.html',
                  {
                      'tform': tform,
                  })

@user_passes_test(lambda u: u.is_staff)
def view_object_eng(request, id):
    object_queryset = Objects_Engagement.objects.filter(engagement=id).order_by('object_id__path', 'object_id__folder', 'object_id__artifact')

    add_breadcrumb(title="Tracked Files, Folders and Artifacts on a Product", top_level=False, request=request)

    return render(request,
                  'dojo/view_objects_eng.html',
                  {
                      'object_queryset': object_queryset,
                      'id': id
                  })
