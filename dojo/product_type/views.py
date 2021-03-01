import logging

from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from dojo.filters import ProductTypeFilter
from dojo.forms import Product_TypeForm, Delete_Product_TypeForm, Add_Product_Type_MemberForm, \
    Edit_Product_Type_MemberForm, Delete_Product_Type_MemberForm
from dojo.models import Product_Type, Product_Type_Member
from dojo.utils import get_page_items, add_breadcrumb
from dojo.notifications.helper import create_notification
from django.db.models import Count, Q
from django.db.models.query import QuerySet
from django.conf import settings
from dojo.authorization.authorization import user_has_permission
from dojo.authorization.roles_permissions import Permissions, Roles
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.product_type.queries import get_authorized_product_types, get_authorized_members
from dojo.product.queries import get_authorized_products

logger = logging.getLogger(__name__)

"""
Jay
Status: in prod
Product Type views
"""


def product_type(request):

    prod_types = get_authorized_product_types(Permissions.Product_Type_View)
    name_words = prod_types.values_list('name', flat=True)

    ptl = ProductTypeFilter(request.GET, queryset=prod_types)
    pts = get_page_items(request, ptl.qs, 25)

    pts.object_list = prefetch_for_product_type(pts.object_list)

    add_breadcrumb(title="Product Type List", top_level=True, request=request)
    return render(request, 'dojo/product_type.html', {
        'name': 'Product Type List',
        'Permissions': Permissions,
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
    else:
        logger.debug('unable to prefetch because query was already executed')

    return prefetch_prod_types


@user_passes_test(lambda u: u.is_staff)
def add_product_type(request):
    form = Product_TypeForm()
    if request.method == 'POST':
        form = Product_TypeForm(request.POST)
        if form.is_valid():
            product_type = form.save()
            if settings.FEATURE_NEW_AUTHORIZATION:
                member = Product_Type_Member()
                member.user = request.user
                member.product_type = product_type
                member.role = Roles.Owner
                member.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product type added successfully.',
                                 extra_tags='alert-success')
            create_notification(event='product_type_added', title=product_type.name,
                                url=reverse('view_product_type', args=(product_type.id,)))
            return HttpResponseRedirect(reverse('product_type'))
    add_breadcrumb(title="Add Product Type", top_level=False, request=request)
    return render(request, 'dojo/new_product_type.html', {
        'name': 'Add Product Type',
        'form': form,
    })


@user_is_authorized(Product_Type, Permissions.Product_Type_View, 'ptid')
def view_product_type(request, ptid):
    pt = get_object_or_404(Product_Type, pk=ptid)
    members = get_authorized_members(pt, Permissions.Product_Type_View)
    products = get_authorized_products(Permissions.Product_View).filter(prod_type=pt)
    add_breadcrumb(title="View Product Type", top_level=False, request=request)
    return render(request, 'dojo/view_product_type.html', {
        'name': 'View Product Type',
        'Permissions': Permissions,
        'pt': pt,
        'products': products,
        'members': members})


@user_is_authorized(Product_Type, Permissions.Product_Type_Delete, 'ptid')
def delete_product_type(request, ptid):
    product_type = get_object_or_404(Product_Type, pk=ptid)
    form = Delete_Product_TypeForm(instance=product_type)

    if request.method == 'POST':
        if 'id' in request.POST and str(product_type.id) == request.POST['id']:
            form = Delete_Product_TypeForm(request.POST, instance=product_type)
            if form.is_valid():
                product_type.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Product Type and relationships removed.',
                                     extra_tags='alert-success')
                create_notification(event='other',
                                title='Deletion of %s' % product_type.name,
                                description='The product type "%s" was deleted by %s' % (product_type.name, request.user),
                                url=request.build_absolute_uri(reverse('product_type')),
                                icon="exclamation-triangle")
                return HttpResponseRedirect(reverse('product_type'))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([product_type])
    rels = collector.nested()

    add_breadcrumb(title="Delete Product Type", top_level=False, request=request)
    return render(request, 'dojo/delete_product_type.html',
                  {'product_type': product_type,
                   'form': form,
                   'rels': rels,
                   })


@user_is_authorized(Product_Type, Permissions.Product_Type_Edit, 'ptid')
def edit_product_type(request, ptid):
    pt = get_object_or_404(Product_Type, pk=ptid)
    authed_users = pt.authorized_users.all()
    members = get_authorized_members(pt, Permissions.Product_Type_Manage_Members)
    pt_form = Product_TypeForm(instance=pt, initial={'authorized_users': authed_users})
    if request.method == "POST" and request.POST.get('edit_product_type'):
        pt_form = Product_TypeForm(request.POST, instance=pt)
        if pt_form.is_valid():
            if not settings.FEATURE_NEW_AUTHORIZATION:
                pt.authorized_users.set(pt_form.cleaned_data['authorized_users'])
            pt = pt_form.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Product type updated successfully.',
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("product_type"))
    add_breadcrumb(title="Edit Product Type", top_level=False, request=request)
    return render(request, 'dojo/edit_product_type.html', {
        'name': 'Edit Product Type',
        'pt_form': pt_form,
        'pt': pt,
        'members': members})


@user_is_authorized(Product_Type, Permissions.Product_Type_Manage_Members, 'ptid')
def add_product_type_member(request, ptid):
    pt = get_object_or_404(Product_Type, pk=ptid)
    memberform = Add_Product_Type_MemberForm(initial={'product_type': pt.id})
    if request.method == 'POST':
        memberform = Add_Product_Type_MemberForm(request.POST, initial={'product_type': pt.id})
        if memberform.is_valid():
            members = Product_Type_Member.objects.filter(product_type=pt, user=memberform.instance.user)
            if members.count() > 0:
                messages.add_message(request,
                                    messages.WARNING,
                                    'Product type member already exists.',
                                    extra_tags='alert-warning')
            elif memberform.instance.role == Roles.Owner and not user_has_permission(request.user, pt, Permissions.Product_Type_Member_Add_Owner):
                messages.add_message(request,
                                    messages.WARNING,
                                    'You are not permitted to add users as owners.',
                                    extra_tags='alert-warning')
            else:
                memberform.save()
                messages.add_message(request,
                                    messages.SUCCESS,
                                    'Product type member added successfully.',
                                    extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_product_type', args=(ptid, )))
    add_breadcrumb(title="Add Product Type Member", top_level=False, request=request)
    return render(request, 'dojo/new_product_type_member.html', {
        'pt': pt,
        'form': memberform,
    })


@user_is_authorized(Product_Type_Member, Permissions.Product_Type_Manage_Members, 'memberid')
def edit_product_type_member(request, memberid):
    member = get_object_or_404(Product_Type_Member, pk=memberid)
    memberform = Edit_Product_Type_MemberForm(instance=member)
    if request.method == 'POST':
        memberform = Edit_Product_Type_MemberForm(request.POST, instance=member)
        if memberform.is_valid():
            if member.role != Roles.Owner:
                owners = Product_Type_Member.objects.filter(product_type=member.product_type, role=Roles.Owner).exclude(id=member.id).count()
                if owners < 1:
                    messages.add_message(request,
                                        messages.SUCCESS,
                                        'There must be at least one owner.',
                                        extra_tags='alert-warning')
                    return HttpResponseRedirect(reverse('view_product_type', args=(member.product_type.id, )))
            if member.role == Roles.Owner and not user_has_permission(request.user, member.product_type, Permissions.Product_Type_Member_Add_Owner):
                messages.add_message(request,
                                    messages.WARNING,
                                    'You are not permitted to make users to owners.',
                                    extra_tags='alert-warning')
            else:
                memberform.save()
                messages.add_message(request,
                                    messages.SUCCESS,
                                    'Product type member updated successfully.',
                                    extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_product_type', args=(member.product_type.id, )))
    add_breadcrumb(title="Edit Product Type Member", top_level=False, request=request)
    return render(request, 'dojo/edit_product_type_member.html', {
        'memberid': memberid,
        'form': memberform,
    })


@user_is_authorized(Product_Type_Member, Permissions.Product_Type_Remove_Member, 'memberid')
def delete_product_type_member(request, memberid):
    member = get_object_or_404(Product_Type_Member, pk=memberid)
    memberform = Delete_Product_Type_MemberForm(instance=member)
    if request.method == 'POST':
        memberform = Delete_Product_Type_MemberForm(request.POST, instance=member)
        member = memberform.instance
        if member.role == Roles.Owner:
            owners = Product_Type_Member.objects.filter(product_type=member.product_type, role=Roles.Owner).count()
            if owners <= 1:
                messages.add_message(request,
                                    messages.SUCCESS,
                                    'There must be at least one owner.',
                                    extra_tags='alert-warning')
                return HttpResponseRedirect(reverse('view_product_type', args=(member.product_type.id, )))

        user = member.user
        member.delete()
        messages.add_message(request,
                            messages.SUCCESS,
                            'Product type member deleted successfully.',
                            extra_tags='alert-success')
        if user == request.user:
            return HttpResponseRedirect(reverse('product_type'))
        else:
            return HttpResponseRedirect(reverse('view_product_type', args=(member.product_type.id, )))
    add_breadcrumb(title="Delete Product Type Member", top_level=False, request=request)
    return render(request, 'dojo/delete_product_type_member.html', {
        'memberid': memberid,
        'form': memberform,
    })
