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
from django.forms import formset_factory, modelformset_factory, inlineformset_factory
from django.db.models import Count, Q

from dojo.filters import ProductFilter, ProductFindingFilter
from dojo.forms import Benchmark_Requirement, Benchmark_Product_SummaryForm, DeleteBenchmarkForm
from dojo.models import Notifications, Dojo_User, Benchmark_Type, Benchmark_Category, \
Benchmark_Requirement, Benchmark_Product, Product, Benchmark_Product_Summary
from dojo.utils import get_page_items, add_breadcrumb, get_punchcard_data, handle_uploaded_selenium, get_system_setting
from dojo.forms import NotificationsForm, BenchmarkForm, Benchmark_RequirementForm
from pprint import pprint

logger = logging.getLogger(__name__)

def add_benchmark(queryset, product):
    requirements = []
    for requirement in queryset:
        benchmark_product = Benchmark_Product()
        benchmark_product.product = product
        benchmark_product.control = requirement
        requirements.append(benchmark_product)

    try:
        Benchmark_Product.objects.bulk_create(requirements)
    except:
        pass

def return_score(queryset):
    asvs_level_1_benchmark = 0
    asvs_level_1_score = 0
    for item in queryset:
        if item["pass_fail"]:
            asvs_level_1_score = item["pass_fail__count"]
        asvs_level_1_benchmark = asvs_level_1_benchmark + item["pass_fail__count"]

    return asvs_level_1_benchmark, asvs_level_1_score


def score_asvs(product, benchmark_type):
    #Compliant to ASVS level 1 benchmarks
    asvs_level_1 = Benchmark_Product.objects.filter(enabled=True, control__enabled=True, product=product, control__category__type=benchmark_type, control__category__enabled=True, control__level_1=True).values('pass_fail').annotate(Count('pass_fail')).order_by()

    asvs_level_1_benchmark, asvs_level_1_score = return_score(asvs_level_1)

    #Compliant to ASVS level 2 benchmarks
    asvs_level_2 = Benchmark_Product.objects.filter(~Q(control__level_1=True), enabled=True, control__enabled=True, product=product, control__category__type=benchmark_type, control__category__enabled=True, control__level_2=True).values('pass_fail').annotate(Count('pass_fail')).order_by()

    asvs_level_2_benchmark, asvs_level_2_score = return_score(asvs_level_2)

    #Compliant to ASVS level 3 benchmarks
    asvs_level_3 = Benchmark_Product.objects.filter(~Q(control__level_1=True), ~Q(control__level_2=True), enabled=True, control__enabled=True, control__category__enabled=True, product=product, control__category__type=benchmark_type, control__level_3=True).values('pass_fail').annotate(Count('pass_fail')).order_by()

    asvs_level_3_benchmark, asvs_level_3_score = return_score(asvs_level_3)

    benchmark_product_summary = Benchmark_Product_Summary.objects.get(product=product, benchmark_type=benchmark_type)

    benchmark_product_summary.asvs_level_1_benchmark = asvs_level_1_benchmark
    benchmark_product_summary.asvs_level_1_score = asvs_level_1_score
    benchmark_product_summary.asvs_level_2_benchmark = asvs_level_2_benchmark
    benchmark_product_summary.asvs_level_2_score = asvs_level_2_score
    benchmark_product_summary.asvs_level_3_benchmark = asvs_level_3_benchmark
    benchmark_product_summary.asvs_level_3_score = asvs_level_3_score

    benchmark_product_summary.save()

@user_passes_test(lambda u: u.is_staff)
def benchmark_view(request, pid, type, cat=None):
    product = get_object_or_404(Product, id=pid)
    benchmark_type = get_object_or_404(Benchmark_Type, id=type)
    benchmark_category = Benchmark_Category.objects.filter(type=type, enabled=True).order_by('name')
    category_name = ""

    #Add requirements to the product
    add_benchmark(Benchmark_Requirement.objects.filter(category__type=type, category__type__enabled=True, enabled=True).all(), product)

    if cat:
        category_name = Benchmark_Category.objects.get(id=cat, enabled=True).name

    #Create the benchmark summary category
    try:
        benchmark_product_summary = Benchmark_Product_Summary.objects.get(product=product, benchmark_type=benchmark_type)
    except:
        pass
        benchmark_product_summary = Benchmark_Product_Summary(product=product, benchmark_type=benchmark_type)
        benchmark_product_summary.save()

    #Insert any new benchmarks since last created
    new_benchmarks = Benchmark_Requirement.objects.filter(category__type=type, category__type__enabled=True, enabled=True).exclude(id__in=Benchmark_Product.objects.filter(product=product).values_list('control_id', flat=True))
    add_benchmark(new_benchmarks, product)

    Benchmark_ProductFormSet = modelformset_factory(Benchmark_Product, exclude=['product, control'], extra=0)

    if request.method == 'POST':
        form = Benchmark_ProductFormSet(request.POST)
        summary_form = Benchmark_Product_SummaryForm(request.POST, instance=benchmark_product_summary)

        if form.is_valid():
            #print summary_form.errors
            summary_form_save = summary_form.save()
            form_save = form.save()
            score_asvs(product, benchmark_type)
            benchmark_product_summary = Benchmark_Product_Summary.objects.get(product=product, benchmark_type=benchmark_type)

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Benchmarks saved.',
                                 extra_tags='alert-success')

    add_breadcrumb(title="Benchmarks", top_level=False, request=request)

    if cat:
        benchmarks = Benchmark_Product.objects.filter(product=product.id, control__category=cat, control__category__enabled=True, control__category__type=type, control__enabled=True).all().order_by('control__objective_number')

        benchmark_formset = Benchmark_ProductFormSet(queryset=Benchmark_Product.objects.filter(product=product.id, control__category=cat, control__category__enabled=True, control__category__type=type, control__enabled=True).all().order_by('control__objective_number'))
    else:
        benchmarks = Benchmark_Product.objects.filter(product=product.id, control__category__enabled=True, control__category__type=type, control__enabled=True).all().order_by('control__category__name', 'control__objective_number')

        benchmark_formset = Benchmark_ProductFormSet(queryset=Benchmark_Product.objects.filter(product=product.id, control__category__enabled=True,control__category__type=type, control__enabled=True).all().order_by('control__category__name', 'control__objective_number'))

    benchmark_summary_form = Benchmark_Product_SummaryForm(instance=benchmark_product_summary)

    return render(request, 'dojo/benchmark.html',
                  {'benchmarks': benchmarks,
                   'benchmark_product_summary': benchmark_product_summary,
                   'benchmark_summary_form': benchmark_summary_form,
                   'benchmark_formset': benchmark_formset,
                   'benchmark_type': benchmark_type,
                   'product': product,
                   'category_name': category_name,
                   'benchmark_category': benchmark_category})

@user_passes_test(lambda u: u.is_staff)
def delete(request, pid, type):
    product = get_object_or_404(Product, id=pid)
    benchmark_type = get_object_or_404(Benchmark_Type, id=type)
    benchmark_product_summary = Benchmark_Product_Summary.objects.filter(product=product, benchmark_type=type).first()
    form = DeleteBenchmarkForm(instance=benchmark_product_summary)
    print form
    from django.contrib.admin.utils import NestedObjects
    from django.db import DEFAULT_DB_ALIAS

    if request.method == 'POST':
        if 'id' in request.POST and str(benchmark_product_summary.id) == request.POST['id']:
            form = DeleteBenchmarkForm(request.POST, instance=benchmark_product_summary)
            if form.is_valid():
                benchmark_product = Benchmark_Product.objects.filter(product=product, control__category__type=type)
                benchmark_product.delete()
                benchmark_product_summary.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Benchmarks removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('product'))

    add_breadcrumb(parent=product, title="Delete Benchmarks", top_level=False, request=request)

    return render(request, 'dojo/delete_benchmark.html',
                  {'product': product,
                   'form': form
                   })
