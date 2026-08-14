# #  product
import logging

from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

from dojo.decorators import deprecated_view
from dojo.tool_config.factory import create_API
from dojo.tool_config.models import Tool_Configuration
from dojo.tool_config.ui.forms import ToolConfigForm
from dojo.utils import add_breadcrumb, dojo_crypto_encrypt

logger = logging.getLogger(__name__)


@deprecated_view("Tool Configuration", removal_version="3.5.0", removal_date="November 2026")
def new_tool_config(request):
    if request.method == "POST":
        tform = ToolConfigForm(request.POST)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            try:
                api = create_API(form_copy)
                if api and hasattr(api, "test_connection"):
                    result = api.test_connection()
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         f"API connection successful with message: {result}.",
                                         extra_tags="alert-success")
                form_copy.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     "Tool Configuration successfully updated.",
                                     extra_tags="alert-success")
                return HttpResponseRedirect(reverse("tool_config"))
            except Exception as e:
                logger.exception("Unable to connect to API")
                messages.add_message(request,
                                     messages.ERROR,
                                     str(e),
                                     extra_tags="alert-danger")
    else:
        tform = ToolConfigForm()
        if "tool_type" in request.GET:
            tform.fields["tool_type"].initial = request.GET.get("tool_type")
        add_breadcrumb(title="New Tool Configuration", top_level=False, request=request)
    return render(request, "dojo/new_tool_config.html",
                  {"tform": tform})


@deprecated_view("Tool Configuration", removal_version="3.5.0", removal_date="November 2026")
def edit_tool_config(request, ttid):
    tool_config = Tool_Configuration.objects.get(pk=ttid)
    # Read before the form binds, which overwrites the instance in place.
    stored = {field: getattr(tool_config, field) for field in ToolConfigForm.CREDENTIAL_FIELDS}
    stored_url = tool_config.url
    if request.method == "POST":
        tform = ToolConfigForm(request.POST, instance=tool_config)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            # A blank credential means "leave it as it is", but only while the URL
            # is unchanged. Pairing a stored secret with a destination submitted in
            # the same request would send it to a host of the editor's choosing.
            reuse = form_copy.url == stored_url
            submitted = tform.cleaned_data
            form_copy.password = stored["password"] if reuse and not submitted["password"] else dojo_crypto_encrypt(submitted["password"])
            form_copy.ssh = stored["ssh"] if reuse and not submitted["ssh"] else dojo_crypto_encrypt(submitted["ssh"])
            form_copy.api_key = stored["api_key"] if reuse and not submitted["api_key"] else submitted["api_key"]
            try:
                api = create_API(form_copy)
                if api and hasattr(api, "test_connection"):
                    result = api.test_connection()
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         f"API connection successful with message: {result}.",
                                         extra_tags="alert-success")
                form_copy.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     "Tool Configuration successfully updated.",
                                     extra_tags="alert-success")
                return HttpResponseRedirect(reverse("tool_config"))
            except Exception as e:
                logger.info(e)
                messages.add_message(request,
                                     messages.ERROR,
                                     str(e),
                                     extra_tags="alert-danger")
    else:
        tform = ToolConfigForm(instance=tool_config)
    add_breadcrumb(title="Edit Tool Configuration", top_level=False, request=request)

    return render(request,
                  "dojo/edit_tool_config.html",
                  {
                      "tform": tform,
                  })


@deprecated_view("Tool Configuration", removal_version="3.5.0", removal_date="November 2026")
def tool_config(request):
    confs = Tool_Configuration.objects.all().order_by("name")
    add_breadcrumb(title="Tool Configuration List", top_level=not len(request.GET), request=request)
    return render(request,
                  "dojo/tool_config.html",
                  {"confs": confs,
                   })
