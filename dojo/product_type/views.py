import logging

from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from dojo.filters import ProductTypeFilter
from dojo.forms import Product_TypeForm, Delete_Product_TypeForm
from dojo.models import Product_Type
from dojo.utils import get_page_items, add_breadcrumb
from dojo.notifications.helper import create_notification
from django.db.models import Count, Q
from django.db.models.query import QuerySet

logger = logging.getLogger(__name__)

"""
Jay
Status: in prod
Product Type views
"""


def product_type(request):
    # query for names outside of query with prefetch to avoid the complex prefetch query from executing twice
    name_words = Product_Type.objects.all().values_list('name', flat=True)

    prod_types = Product_Type.objects.all()

    ptl = ProductTypeFilter(request.GET, queryset=prod_types)
    pts = get_page_items(request, ptl.qs, 25)

    pts.object_list = prefetch_for_product_type(pts.object_list)

    add_breadcrumb(title="Product Type List", top_level=True, request=request)
    return render(request, 'dojo/product_type.html', {
        'name': 'Product Type List',
        'metric': False,
        'user': request.user,
        'pts': pts,
        'ptl': ptl,
        'name_words': name_words})


def prefetch_for_product_type(prod_types):
    prefetch_prod_types = prod_types

    if isinstance(prefetch_prod_types, QuerySet):  # old code can arrive here with prods being a list because the query was already executed
        active_findings_query = Q(prod_type__engagement__test__finding__active=True)
        active_verified_findings_query = Q(prod_type__engagement__test__finding__active=True,
                                prod_type__engagement__test__finding__verified=True)
        prefetch_prod_types = prefetch_prod_types.prefetch_related('authorized_users')
        prefetch_prod_types = prefetch_prod_types.annotate(
            active_findings_count=Count('prod_type__engagement__test__finding__id', filter=active_findings_query))
        prefetch_prod_types = prefetch_prod_types.annotate(
            active_verified_findings_count=Count('prod_type__engagement__test__finding__id', filter=active_verified_findings_query))
        prefetch_prod_types = prefetch_prod_types.annotate(prod_count=Count('prod_type', distinct=True))
        prefetch_prod_types = prefetch_prod_types.annotate(user_count=Count('authorized_users', distinct=True))
    else:
        logger.debug('unable to prefetch because query was already executed')

    return prefetch_prod_types


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
    authed_users = pt.authorized_users.all()
    pt_form = Product_TypeForm(instance=pt, initial={'authorized_users': authed_users})
    delete_pt_form = Delete_Product_TypeForm(instance=pt)
    if request.method == "POST" and request.POST.get('edit_product_type'):
        pt_form = Product_TypeForm(request.POST, instance=pt)
        if pt_form.is_valid():
            pt.authorized_users.set(pt_form.cleaned_data['authorized_users'])
            pt = pt_form.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Product type updated successfully.',
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("product_type"))
    if request.method == "POST" and request.POST.get("delete_product_type"):
        form2 = Delete_Product_TypeForm(request.POST, instance=pt)
        if form2.is_valid():
            pt.delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Product type Deleted successfully.",
                extra_tags="alert-success",
            )
            create_notification(event='other',
                                title='Deletion of %s' % pt.name,
                                description='The product type "%s" was deleted by %s' % (pt.name, request.user),
                                url=request.build_absolute_uri(reverse('product_type')),
                                icon="exclamation-triangle")
            return HttpResponseRedirect(reverse("product_type"))
    add_breadcrumb(title="Edit Product Type", top_level=False, request=request)
    return render(request, 'dojo/edit_product_type.html', {
        'name': 'Edit Product Type',
        'metric': False,
        'user': request.user,
        'pt_form': pt_form,
        'pt': pt})
