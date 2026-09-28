"""
Classic (Django-rendered) CRUD for the three asset attribute lookup tables.

The rich editor lives in the Vue Pro UI; these views give open-source installs and
admins a functional fallback, mirroring the Development_Environment ("Environments")
screens. All three lookups share generic list/add/edit helpers driven by ``_CONFIG``.
"""
import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models.deletion import RestrictedError
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.authorization.authorization import user_has_configuration_permission_or_403
from dojo.product_attributes.models import Product_Lifecycle, Product_Origin, Product_Platform
from dojo.product_attributes.ui.forms import (
    DeleteProductAttributeOptionForm,
    ProductLifecycleForm,
    ProductOriginForm,
    ProductPlatformForm,
)
from dojo.utils import add_breadcrumb, get_page_items

logger = logging.getLogger(__name__)

_CONFIG = {
    "platform": {
        "model": Product_Platform,
        "form": ProductPlatformForm,
        "label": "Platform",
        "label_plural": "Platforms",
        "model_name": "product_platform",
        "list_url": "product_platforms",
        "add_url": "add_product_platform",
        "edit_url": "edit_product_platform",
    },
    "lifecycle": {
        "model": Product_Lifecycle,
        "form": ProductLifecycleForm,
        "label": "Lifecycle",
        "label_plural": "Lifecycles",
        "model_name": "product_lifecycle",
        "list_url": "product_lifecycles",
        "add_url": "add_product_lifecycle",
        "edit_url": "edit_product_lifecycle",
    },
    "origin": {
        "model": Product_Origin,
        "form": ProductOriginForm,
        "label": "Origin",
        "label_plural": "Origins",
        "model_name": "product_origin",
        "list_url": "product_origins",
        "add_url": "add_product_origin",
        "edit_url": "edit_product_origin",
    },
}


def _context(cfg):
    return {
        "label": cfg["label"],
        "label_plural": cfg["label_plural"],
        "model_name": cfg["model_name"],
        "list_url": cfg["list_url"],
        "add_url": cfg["add_url"],
        "edit_url": cfg["edit_url"],
    }


def _list(request, kind):
    cfg = _CONFIG[kind]
    options = get_page_items(request, cfg["model"].objects.all().order_by("display_order", "name"), 25)
    add_breadcrumb(title=f"{cfg['label']} List", top_level=True, request=request)
    ctx = _context(cfg)
    ctx["options"] = options
    return render(request, "dojo/product_attribute_list.html", ctx)


def _add(request, kind):
    cfg = _CONFIG[kind]
    user_has_configuration_permission_or_403(request.user, f"dojo.add_{cfg['model_name']}")
    form = cfg["form"]()
    if request.method == "POST":
        form = cfg["form"](request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request, messages.SUCCESS,
                                 _("%(label)s added successfully.") % {"label": cfg["label"]},
                                 extra_tags="alert-success")
            return HttpResponseRedirect(reverse(cfg["list_url"]))
    add_breadcrumb(title=f"Add {cfg['label']}", top_level=False, request=request)
    ctx = _context(cfg)
    ctx["form"] = form
    return render(request, "dojo/product_attribute_add.html", ctx)


def _edit(request, kind, pk):
    cfg = _CONFIG[kind]
    option = get_object_or_404(cfg["model"], pk=pk)
    form = cfg["form"](instance=option)
    delete_form = DeleteProductAttributeOptionForm(initial={"id": option.id})
    edit_key = f"edit_{cfg['model_name']}"
    delete_key = f"delete_{cfg['model_name']}"
    if request.method == "POST" and request.POST.get(edit_key):
        user_has_configuration_permission_or_403(request.user, f"dojo.change_{cfg['model_name']}")
        form = cfg["form"](request.POST, instance=option)
        if form.is_valid():
            form.save()
            messages.add_message(request, messages.SUCCESS,
                                 _("%(label)s updated successfully.") % {"label": cfg["label"]},
                                 extra_tags="alert-success")
            return HttpResponseRedirect(reverse(cfg["list_url"]))
    if request.method == "POST" and request.POST.get(delete_key):
        user_has_configuration_permission_or_403(request.user, f"dojo.delete_{cfg['model_name']}")
        try:
            option.delete()
            messages.add_message(request, messages.SUCCESS,
                                 _("%(label)s deleted successfully.") % {"label": cfg["label"]},
                                 extra_tags="alert-success")
        except RestrictedError as err:
            messages.add_message(request, messages.WARNING,
                                 f"{cfg['label']} cannot be deleted: {err}",
                                 extra_tags="alert-warning")
        return HttpResponseRedirect(reverse(cfg["list_url"]))
    add_breadcrumb(title=f"Edit {cfg['label']}", top_level=False, request=request)
    ctx = _context(cfg)
    ctx["form"] = form
    ctx["delete_form"] = delete_form
    ctx["option"] = option
    return render(request, "dojo/product_attribute_edit.html", ctx)


# ---- platform ----
@login_required
def list_platforms(request):
    return _list(request, "platform")


@login_required
def add_platform(request):
    return _add(request, "platform")


@login_required
def edit_platform(request, pk):
    return _edit(request, "platform", pk)


# ---- lifecycle ----
@login_required
def list_lifecycles(request):
    return _list(request, "lifecycle")


@login_required
def add_lifecycle(request):
    return _add(request, "lifecycle")


@login_required
def edit_lifecycle(request, pk):
    return _edit(request, "lifecycle", pk)


# ---- origin ----
@login_required
def list_origins(request):
    return _list(request, "origin")


@login_required
def add_origin(request):
    return _add(request, "origin")


@login_required
def edit_origin(request, pk):
    return _edit(request, "origin", pk)
