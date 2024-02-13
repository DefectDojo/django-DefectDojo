# #  product
import logging
from django.contrib import messages
from django.core.exceptions import BadRequest
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.shortcuts import render, get_object_or_404
from django.utils.translation import gettext as _

from dojo.forms import DeleteToolProductSettingsForm, ToolProductSettingsForm
from dojo.models import Product, Tool_Product_Settings
from dojo.utils import Product_Tab
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions

logger = logging.getLogger(__name__)


@user_is_authorized(Product, Permissions.Product_Edit, 'pid')
def new_tool_product(request, pid):
    prod = get_object_or_404(Product, id=pid)
    if request.method == 'POST':
        tform = ToolProductSettingsForm(request.POST)
        if tform.is_valid():
            # form.tool_type = tool_type
            new_prod = tform.save(commit=False)
            new_prod.product = prod
            new_prod.save()

            messages.add_message(
                request,
                messages.SUCCESS,
                _('Product Tool Configuration Successfully Created.'),
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('all_tool_product', args=(pid, )))
    else:
        tform = ToolProductSettingsForm()
    product_tab = Product_Tab(prod, title=_("Tool Configurations"), tab="settings")
    return render(request, 'dojo/new_tool_product.html', {
        'tform': tform,
        'product_tab': product_tab,
        'pid': pid
    })


@user_is_authorized(Product, Permissions.Product_Edit, 'pid')
def all_tool_product(request, pid):
    prod = get_object_or_404(Product, id=pid)
    tools = Tool_Product_Settings.objects.filter(product=prod).order_by('name')
    product_tab = Product_Tab(prod, title=_("Tool Configurations"), tab="settings")
    return render(request, 'dojo/view_tool_product_all.html', {
        'prod': prod,
        'tools': tools,
        'product_tab': product_tab
    })


@user_is_authorized(Product, Permissions.Product_Edit, 'pid')
def edit_tool_product(request, pid, ttid):
    product = get_object_or_404(Product, id=pid)
    tool_product = Tool_Product_Settings.objects.get(pk=ttid)
    if tool_product.product != product:
        raise BadRequest(f'Product {pid} does not fit to product of Tool_Product {tool_product.product.id}')

    if request.method == 'POST':
        tform = ToolProductSettingsForm(request.POST, instance=tool_product)
        if tform.is_valid():
            tform.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                _('Tool Product Configuration Successfully Updated.'),
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('all_tool_product', args=(pid, )))
    else:
        tform = ToolProductSettingsForm(instance=tool_product)

    product_tab = Product_Tab(product, title=_("Edit Product Tool Configuration"), tab="settings")
    return render(request, 'dojo/edit_tool_product.html', {
        'tform': tform,
        'product_tab': product_tab
    })


@user_is_authorized(Product, Permissions.Product_Edit, 'pid')
def delete_tool_product(request, pid, ttid):
    tool_product = Tool_Product_Settings.objects.get(pk=ttid)
    product = get_object_or_404(Product, id=pid)
    if tool_product.product != product:
        raise BadRequest(f'Product {pid} does not fit to product of Tool_Product {tool_product.product.id}')

    if request.method == 'POST':
        DeleteToolProductSettingsForm(request.POST, instance=tool_product)
        tool_product.delete()
        messages.add_message(
            request,
            messages.SUCCESS,
            _('Tool Product Successfully Deleted.'),
            extra_tags='alert-success')
        return HttpResponseRedirect(reverse('all_tool_product', args=(pid, )))
    else:
        tform = ToolProductSettingsForm(instance=tool_product)

    product_tab = Product_Tab(product, title=_("Delete Product Tool Configuration"), tab="settings")

    return render(request, 'dojo/delete_tool_product.html', {
        'tform': tform,
        'product_tab': product_tab
    })
