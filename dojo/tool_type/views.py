# #  product
import logging

from django.contrib import messages
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils.translation import gettext as _

from dojo.utils import add_breadcrumb
from dojo.forms import ToolTypeForm
from dojo.models import Tool_Type
from dojo.authorization.authorization_decorators import user_is_configuration_authorized

logger = logging.getLogger(__name__)


@user_is_configuration_authorized('dojo.add_tool_type')
def new_tool_type(request):
    if request.method == 'POST':
        tform = ToolTypeForm(request.POST, instance=Tool_Type())
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Tool Type Configuration Successfully Created.'),
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('tool_type', ))
    else:
        tform = ToolTypeForm()
        add_breadcrumb(title=_("New Tool Type Configuration"), top_level=False, request=request)

    return render(request, 'dojo/new_tool_type.html', {'tform': tform})


@user_is_configuration_authorized('dojo.change_tool_type')
def edit_tool_type(request, ttid):
    tool_type = Tool_Type.objects.get(pk=ttid)
    if request.method == 'POST':
        tform = ToolTypeForm(request.POST, instance=tool_type)
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Tool Type successfully updated.'),
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('tool_type', ))
    else:
        tform = ToolTypeForm(instance=tool_type)

    add_breadcrumb(title=_("Edit Tool Type"), top_level=False, request=request)

    return render(request, 'dojo/edit_tool_type.html', {'tform': tform})


@user_is_configuration_authorized('dojo.view_tool_type')
def tool_type(request):
    confs = Tool_Type.objects.all().order_by('name')
    add_breadcrumb(title=_("Tool Type List"), top_level=not len(request.GET), request=request)

    return render(request, 'dojo/tool_type.html', {'confs': confs})
