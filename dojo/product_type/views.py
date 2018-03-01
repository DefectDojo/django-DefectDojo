# #  product type
import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from dojo.filters import ProductTypeFilter
from dojo.forms import Product_TypeForm, Product_TypeProductForm
from dojo.models import Product_Type
from dojo.utils import get_page_items, add_breadcrumb, get_system_setting

logger = logging.getLogger(__name__)

"""
Jay
Status: in prod
Product Type views
"""


def product_type(request):
    initial_queryset = Product_Type.objects.all().order_by('name')
    name_words = [product.name for product in
                  initial_queryset]

    ptl = ProductTypeFilter(request.GET, queryset=initial_queryset)
    pts = get_page_items(request, ptl.qs, 25)
    add_breadcrumb(title="Product Type List", top_level=True, request=request)
    return render(request, 'dojo/product_type.html', {
        'name': 'Product Type List',
        'metric': False,
        'user': request.user,
        'pts': pts,
        'ptl': ptl,
        'name_words': name_words})


@user_passes_test(lambda u: u.is_staff)
def add_product_type(request):
    form = Product_TypeForm()
    if request.method == 'POST':
        form = Product_TypeForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product type added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('product_type'))
    add_breadcrumb(title="Add Product Type", top_level=False, request=request)
    return render(request, 'dojo/new_product_type.html', {
        'name': 'Add Product Type',
        'metric': False,
        'user': request.user,
        'form': form,
    })


@user_passes_test(lambda u: u.is_staff)
def edit_product_type(request, ptid):
    pt = get_object_or_404(Product_Type, pk=ptid)
    form = Product_TypeForm(instance=pt)
    if request.method == 'POST':
        form = Product_TypeForm(request.POST, instance=pt)
        if form.is_valid():
            pt = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product type updated successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('product_type'))
    add_breadcrumb(title="Edit Product Type", top_level=False, request=request)
    return render(request, 'dojo/edit_product_type.html', {
        'name': 'Edit Product Type',
        'metric': False,
        'user': request.user,
        'form': form,
        'pt': pt})


@user_passes_test(lambda u: u.is_staff)
def add_product_to_product_type(request, ptid):
    pt = get_object_or_404(Product_Type, pk=ptid)
    form = Product_TypeProductForm(initial={'prod_type': pt})
    add_breadcrumb(title="New %s Product" % pt.name, top_level=False, request=request)
    return render(request, 'dojo/new_product.html',
                  {'form': form,
                   })
