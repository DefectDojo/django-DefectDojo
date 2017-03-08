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
from pytz import timezone

from dojo.filters import ProductFilter, ProductFindingFilter
from dojo.forms import ProductForm, EngForm, DeleteProductForm
from dojo.models import Product_Type, Finding, Product, Engagement, ScanSettings, Risk_Acceptance, Cred_User, Cred_Mapping
from dojo.utils import get_page_items, add_breadcrumb, get_punchcard_data
from dojo.models import *
from dojo.models import *
from dojo.forms import *
from dojo.tasks import *
from dojo.forms import *
from dojo.utils import dojo_crypto_encrypt, prepare_for_view
from dojo.product import views as ds

localtz = timezone(settings.TIME_ZONE)

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)

@user_passes_test(lambda u: u.is_staff)
def new_cred(request):
    if request.method == 'POST':
        tform = CredUserForm(request.POST)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            form_copy.password = dojo_crypto_encrypt(tform.cleaned_data['password'])
            form_copy.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Credential Successfully Created.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('cred', ))
    else:
        tform = CredUserForm()
        add_breadcrumb(title="New Credential", top_level=False, request=request)
    return render(request, 'dojo/new_cred.html',
                  {'tform': tform})

@user_passes_test(lambda u: u.is_staff)
def edit_cred(request, ttid):
    tool_config = Cred_User.objects.get(pk=ttid)
    if request.method == 'POST':
        tform = CredUserForm(request.POST, instance=tool_config)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            form_copy.password = dojo_crypto_encrypt(tform.cleaned_data['password'])
            form_copy.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Credential Successfully Updated.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('cred', ))
    else:
        tool_config.password = prepare_for_view(tool_config.password)

        tform = CredUserForm(instance=tool_config)
    add_breadcrumb(title="Edit Credential Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/edit_cred.html',
                  {
                      'tform': tform,
                  })

@user_passes_test(lambda u: u.is_staff)
def view_cred_details(request, ttid):
    cred = Cred_User.objects.get(pk=ttid)
    notes = cred.notes.all()
    cred_products = Cred_Mapping.objects.select_related('product').filter(product_id__isnull=False, cred_id=ttid).order_by('product__name')

    if request.method == 'POST':
        form = NoteForm(request.POST)

        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = datetime.now(tz=localtz)
            new_note.save()
            cred.notes.add(new_note)
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

    add_breadcrumb(title="View", top_level=False, request=request)

    return render(request,
                  'dojo/view_cred_details.html',
                  {
                      'cred': cred,
                      'form': form,
                      'notes': notes,
                      'cred_products': cred_products
                  })

@user_passes_test(lambda u: u.is_staff)
def cred(request):
    confs = Cred_User.objects.all().order_by('name', 'environment', 'username')
    add_breadcrumb(title="Credential Manager", top_level=True, request=request)
    return render(request,
                  'dojo/view_cred.html',
                  {'confs': confs,
                   })

@user_passes_test(lambda u: u.is_staff)
def view_cred_product(request, pid, ttid):
    cred = get_object_or_404(Cred_Mapping.objects.select_related('cred_id'), id=ttid)
    notes = cred.cred_id.notes.all()

    if request.method == 'POST':
        form = NoteForm(request.POST)

        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = datetime.now(tz=localtz)
            new_note.save()
            cred.cred_id.notes.add(new_note)
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

    add_breadcrumb(title="Credential Manager", top_level=False, request=request)

    return render(request,
                  'dojo/view_cred_product.html',
                  {
                      'cred': cred,
                      'form': form,
                      'notes': notes
                  })

@user_passes_test(lambda u: u.is_staff)
def edit_cred_product(request, pid, ttid):
    #cred = get_object_or_404(Cred_Mapping.objects.select_related('cred_id'), id=ttid)
    cred = Cred_Mapping.objects.get(pk=ttid)

    if request.method == 'POST':
        tform = CredMappingForm(request.POST, instance=cred)
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Credential Successfully Updated.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    else:
        tform = CredMappingForm(instance=cred)

    add_breadcrumb(title="Edit Credential Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/edit_cred_product.html',
                  {
                      'tform': tform,
                  })

@user_passes_test(lambda u: u.is_staff)
def new_cred_product(request, pid):

    if request.method == 'POST':
        tform = CredMappingForm(request.POST)
        if tform.is_valid():
            prod = Product.objects.get(id=pid)
            new_f = tform.save(commit=False)
            new_f.product = prod
            new_f.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Credential Successfully Updated.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    else:
        tform = CredMappingForm()

    add_breadcrumb(title="Add Credential Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/new_cred_product.html',
                  {
                      'tform': tform,
                      'pid': pid
                  })

@user_passes_test(lambda u: u.is_staff)
def delete_cred_product(request, pid, ttid):
    cred = Cred_Mapping.objects.get(pk=ttid)

    if request.method == 'POST':
        tform = CredMappingForm(request.POST, instance=cred)
        cred.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             'Credential Successfully Deleted.',
                             extra_tags='alert-success')
        return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    else:
        tform = CredMappingForm(instance=cred)

    add_breadcrumb(title="Delete Credential", top_level=False, request=request)

    return render(request,
                  'dojo/delete_cred_product.html',
                  {
                      'tform': tform,
                  })
