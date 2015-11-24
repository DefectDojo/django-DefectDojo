# #  product
import logging
from datetime import datetime
from math import ceil

from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from pytz import timezone

from dojo.filters import ProductFilter, ProductFindingFilter
from dojo.forms import ProductForm, EngForm, DeleteProductForm
from dojo.models import Product_Type, Finding, Product, Engagement, ScanSettings, Risk_Acceptance
from dojo.utils import get_page_items, add_breadcrumb, get_punchcard_data

localtz = timezone(settings.TIME_ZONE)

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)


def product(request):
    if request.user.is_staff:
        initial_queryset = Product.objects.all()
        name_words = [product.name for product in
                      Product.objects.all()]
    else:
        initial_queryset = Product.objects.filter(
            authorized_users__in=[request.user])
        name_words = [word for product in
                      Product.objects.filter(
                          authorized_users__in=[request.user])
                      for word in product.name.split() if len(word) > 2]

    product_type = None
    if 'prod_type' in request.GET:
        p = request.GET.getlist('prod_type', [])
        if len(p) == 1:
            product_type = get_object_or_404(Product_Type, id=p[0])

    prods = ProductFilter(request.GET, queryset=initial_queryset, user=request.user)
    prod_list = get_page_items(request, prods, 25)
    add_breadcrumb(title="Product List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/product.html',
                  {'prod_list': prod_list,
                   'prods': prods,
                   'name_words': sorted(set(name_words)),
                   'user': request.user})


def view_product(request, pid):
    prod = get_object_or_404(Product, id=pid)
    engs = Engagement.objects.filter(product=prod, active=True)
    i_engs = Engagement.objects.filter(product=prod, active=False)
    scan_sets = ScanSettings.objects.filter(product=prod)
    auth = request.user.is_staff or request.user in prod.authorized_users.all()
    if not auth:
        # will render 403
        raise PermissionDenied

    try:
        start_date = Finding.objects.filter(test__engagement__product=prod).order_by('date')[:1][0].date
    except:
        start_date = localtz.localize(datetime.today())

    end_date = localtz.localize(datetime.today())

    risk_acceptances = Risk_Acceptance.objects.filter(engagement__in=Engagement.objects.filter(product=prod))

    accepted_findings = [finding for ra in risk_acceptances
                         for finding in ra.accepted_findings.all()]

    verified_findings = Finding.objects.filter(test__engagement__product=prod,
                                               date__range=[start_date, end_date],
                                               false_p=False,
                                               verified=True,
                                               duplicate=False,
                                               out_of_scope=False)

    open_findings = Finding.objects.filter(test__engagement__product=prod,
                                           date__range=[start_date, end_date],
                                           false_p=False,
                                           verified=True,
                                           duplicate=False,
                                           out_of_scope=False,
                                           active=True,
                                           mitigated__isnull=True)

    closed_findings = Finding.objects.filter(test__engagement__product=prod,
                                             date__range=[start_date, end_date],
                                             false_p=False,
                                             verified=True,
                                             duplicate=False,
                                             out_of_scope=False,
                                             mitigated__isnull=False)

    start_date = localtz.localize(datetime.combine(start_date, datetime.min.time()))

    r = relativedelta(end_date, start_date)
    weeks_between = int(ceil((((r.years * 12) + r.months) * 4.33) + (r.days / 7)))
    if weeks_between <= 0:
        weeks_between += 2

    punchcard, ticks, highest_count = get_punchcard_data(verified_findings, weeks_between, start_date)
    add_breadcrumb(parent=prod, top_level=False, request=request)
    return render(request,
                  'dojo/view_product.html',
                  {'prod': prod,
                   'engs': engs,
                   'i_engs': i_engs,
                   'scan_sets': scan_sets,
                   'verified_findings': verified_findings,
                   'open_findings': open_findings,
                   'closed_findings': closed_findings,
                   'accepted_findings': accepted_findings,
                   'punchcard': punchcard,
                   'ticks': ticks,
                   'highest_count': highest_count,
                   'user': request.user,
                   'authorized': auth})


@user_passes_test(lambda u: u.is_staff)
def new_product(request):
    if request.method == 'POST':
        form = ProductForm(request.POST)
        if form.is_valid():
            product = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_product', args=(product.id,)))
    else:
        form = ProductForm()
    add_breadcrumb(title="New Product", top_level=False, request=request)
    return render(request, 'dojo/new_product.html',
                  {'form': form})


@user_passes_test(lambda u: u.is_staff)
def edit_product(request, pid):
    prod = Product.objects.get(pk=pid)
    if request.method == 'POST':
        form = ProductForm(request.POST, instance=prod)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product updated successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    else:
        form = ProductForm(instance=prod,
                           initial={'auth_users': prod.authorized_users.all()})

    add_breadcrumb(parent=prod, title="Edit", top_level=False, request=request)

    return render(request,
                  'dojo/edit_product.html',
                  {'form': form,
                   'product': prod,
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_product(request, pid):
    product = get_object_or_404(Product, pk=pid)
    form = DeleteProductForm(instance=product)

    from django.contrib.admin.util import NestedObjects
    from django.db import DEFAULT_DB_ALIAS

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([product])
    rels = collector.nested()

    if request.method == 'POST':
        if 'id' in request.POST and str(product.id) == request.POST['id']:
            form = DeleteProductForm(request.POST, instance=product)
            if form.is_valid():
                product.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Product and relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('product'))

    add_breadcrumb(parent=product, title="Delete", top_level=False, request=request)

    return render(request, 'dojo/delete_product.html',
                  {'product': product,
                   'form': form,
                   'rels': rels,
                   })


"""
Greg
Status: in production
"""


def all_product_findings(request, pid):
    p = get_object_or_404(Product, id=pid)
    result = ProductFindingFilter(
        request.GET,
        queryset=Finding.objects.filter(test__engagement__product=p,
                                        active=True,
                                        verified=True))
    page = get_page_items(request, result, 25)

    add_breadcrumb(title="Open findings", top_level=False, request=request)

    return render(request,
                  "dojo/all_product_findings.html",
                  {"findings": page,
                   "product": p,
                   "filtered": result,
                   "user": request.user,
                   })


@user_passes_test(lambda u: u.is_staff)
def new_eng_for_app(request, pid):
    prod = Product.objects.get(id=pid)
    if request.method == 'POST':
        form = EngForm(request.POST)
        if form.is_valid():
            new_eng = form.save(commit=False)
            new_eng.product = prod
            if new_eng.threat_model:
                new_eng.progress = 'threat_model'
            else:
                new_eng.progress = 'other'
            new_eng.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Engagement added successfully.',
                                 extra_tags='alert-success')
            if "_Add Tests" in request.POST:
                return HttpResponseRedirect(reverse('add_tests', args=(new_eng.id,)))
            else:
                return HttpResponseRedirect(reverse('view_engagement', args=(new_eng.id,)))
    else:
        form = EngForm(initial={})

    add_breadcrumb(parent=prod, title="New Engagement", top_level=False, request=request)

    return render(request, 'dojo/new_eng.html',
                  {'form': form, 'pid': pid,
                   })
