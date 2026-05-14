import logging
from functools import partial

from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.core.exceptions import PermissionDenied
from django.db import DEFAULT_DB_ALIAS
from django.db.models import OuterRef, Value
from django.db.models.functions import Coalesce
from django.db.models.query import QuerySet
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.roles_permissions import Permissions
from dojo.filters import ProductFilter, ProductFilterWithoutObjectLookups, ProductTypeFilter
from dojo.forms import (
    Add_Product_Type_AuthorizedUsersForm,
    Delete_Product_TypeForm,
    Product_TypeForm,
)
from dojo.labels import get_labels
from dojo.models import Dojo_User, Finding, Product, Product_Type
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import (
    get_authorized_product_types,
)
from dojo.query_utils import build_count_subquery
from dojo.utils import (
    add_breadcrumb,
    async_delete,
    get_page_items,
    get_setting,
    get_system_setting,
)

logger = logging.getLogger(__name__)

"""
Jay
Status: in prod
Product Type views
"""

labels = get_labels()


def product_type(request):
    prod_types = get_authorized_product_types("view")
    name_words = prod_types.values_list("name", flat=True)

    ptl = ProductTypeFilter(request.GET, queryset=prod_types)
    pts = get_page_items(request, ptl.qs, 25)

    pts.object_list = prefetch_for_product_type(pts.object_list)

    page_name = str(labels.ORG_READ_LIST_LABEL)
    add_breadcrumb(title=page_name, top_level=True, request=request)

    return render(request, "dojo/product_type.html", {
        "name": page_name,
        "pts": pts,
        "ptl": ptl,
        "name_words": name_words})


def prefetch_for_product_type(prod_types):
    # old code can arrive here with prods being a list because the query was already executed
    if not isinstance(prod_types, QuerySet):
        logger.debug("unable to prefetch because query was already executed")
        return prod_types

    prod_subquery = build_count_subquery(
        Product.objects.filter(prod_type_id=OuterRef("pk")),
        group_field="prod_type_id",
    )
    base_findings = Finding.objects.filter(test__engagement__product__prod_type_id=OuterRef("pk"))
    count_subquery = partial(build_count_subquery, group_field="test__engagement__product__prod_type_id")

    return prod_types.annotate(
        prod_count=Coalesce(prod_subquery, Value(0)),
        active_findings_count=Coalesce(count_subquery(base_findings.filter(active=True)), Value(0)),
        active_verified_findings_count=Coalesce(
            count_subquery(base_findings.filter(active=True, verified=True)), Value(0),
        ),
    )


def add_product_type(request):
    page_name = str(labels.ORG_CREATE_LABEL)
    form = Product_TypeForm()
    if request.method == "POST":
        form = Product_TypeForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 str(labels.ORG_CREATE_SUCCESS_MESSAGE),
                                 extra_tags="alert-success")
            return HttpResponseRedirect(reverse("product_type"))
    add_breadcrumb(title=page_name, top_level=False, request=request)

    return render(request, "dojo/new_product_type.html", {
        "name": page_name,
        "form": form,
    })


def view_product_type(request, ptid):
    page_name = str(labels.ORG_READ_LABEL)
    pt = get_object_or_404(Product_Type, pk=ptid)
    authorized_users = pt.authorized_users.order_by("first_name", "last_name", "username")
    products = get_authorized_products("view").filter(prod_type=pt)
    filter_string_matching = get_system_setting("filter_string_matching", False)
    filter_class = ProductFilterWithoutObjectLookups if filter_string_matching else ProductFilter
    prod_filter = filter_class(request.GET, queryset=products, user=request.user)
    products = get_page_items(request, prod_filter.qs, 25)

    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, "dojo/view_product_type.html", {
        "name": page_name,
        "pt": pt,
        "products": products,
        "prod_filter": prod_filter,
        "authorized_users": authorized_users,
    })


def delete_product_type(request, ptid):
    product_type = get_object_or_404(Product_Type, pk=ptid)
    form = Delete_Product_TypeForm(instance=product_type)

    if request.method == "POST":
        if "id" in request.POST and str(product_type.id) == request.POST["id"]:
            form = Delete_Product_TypeForm(request.POST, instance=product_type)
            if form.is_valid():
                if get_setting("ASYNC_OBJECT_DELETE"):
                    async_del = async_delete()
                    async_del.delete(product_type)
                    message = labels.ORG_DELETE_SUCCESS_ASYNC_MESSAGE
                else:
                    message = labels.ORG_DELETE_SUCCESS_MESSAGE
                    product_type.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     message,
                                     extra_tags="alert-success")
                return HttpResponseRedirect(reverse("product_type"))

    rels = [_("Previewing the relationships has been disabled."), ""]
    display_preview = get_setting("DELETE_PREVIEW")
    if display_preview:
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([product_type])
        rels = collector.nested()

    add_breadcrumb(title=str(labels.ORG_DELETE_LABEL), top_level=False, request=request)
    return render(request, "dojo/delete_product_type.html", {
        "label_delete_with_name": labels.ORG_DELETE_WITH_NAME_LABEL % {"name": product_type},
        "form": form,
        "rels": rels,
    })


def edit_product_type(request, ptid):
    page_name = str(labels.ORG_UPDATE_LABEL)
    pt = get_object_or_404(Product_Type, pk=ptid)
    pt_form = Product_TypeForm(instance=pt)
    if request.method == "POST" and request.POST.get("edit_product_type"):
        pt_form = Product_TypeForm(request.POST, instance=pt)
        if pt_form.is_valid():
            pt = pt_form.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                labels.ORG_UPDATE_SUCCESS_MESSAGE,
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("product_type"))

    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, "dojo/edit_product_type.html", {
        "name": page_name,
        "label_edit_with_name": labels.ORG_UPDATE_WITH_NAME_LABEL % {"name": pt.name},
        "pt_form": pt_form,
        "pt": pt})


def add_product_type_authorized_users(request, ptid):
    pt = get_object_or_404(Product_Type, pk=ptid)
    user_has_permission_or_403(request.user, pt, Permissions.Product_Type_Manage_Members)
    page_name = _("Add Authorized Users")
    form = Add_Product_Type_AuthorizedUsersForm(product_type=pt)
    if request.method == "POST":
        form = Add_Product_Type_AuthorizedUsersForm(request.POST, product_type=pt)
        if form.is_valid():
            users = form.cleaned_data["users"]
            pt.authorized_users.add(*users)
            messages.add_message(
                request, messages.SUCCESS,
                _("Added %(count)d user(s) to authorized users.") % {"count": len(users)},
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_product_type", args=(ptid,)))
    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, "dojo/new_product_type_authorized_users.html", {
        "name": page_name,
        "pt": pt,
        "form": form,
    })


def delete_product_type_authorized_user(request, ptid, user_id):
    pt = get_object_or_404(Product_Type, pk=ptid)
    user_has_permission_or_403(request.user, pt, Permissions.Product_Type_Manage_Members)
    if request.method != "POST":
        raise PermissionDenied
    user = get_object_or_404(Dojo_User, pk=user_id)
    pt.authorized_users.remove(user)
    messages.add_message(
        request, messages.SUCCESS,
        _("Removed %(username)s from authorized users.") % {"username": user.username},
        extra_tags="alert-success",
    )
    return HttpResponseRedirect(reverse("view_product_type", args=(ptid,)))
