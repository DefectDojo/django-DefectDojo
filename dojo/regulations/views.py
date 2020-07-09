# #  product
import logging

from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from dojo.utils import add_breadcrumb
from dojo.forms import ToolTypeForm
from dojo.models import Regulation


logger = logging.getLogger(__name__)

@user_passes_test(lambda u: u.is_staff)
def new_regulation(request):
    # if request.method == 'POST':
    #     tform = ToolTypeForm(request.POST, instance=Tool_Type())
    #     if tform.is_valid():
    #         tform.save()
    #         messages.add_message(request,
    #                              messages.SUCCESS,
    #                              'Tool Type Configuration Successfully Created.',
    #                              extra_tags='alert-success')
    #         return HttpResponseRedirect(reverse('tool_type', ))
    # else:
    #     tform = ToolTypeForm()
    #     add_breadcrumb(title="New Tool Type Configuration", top_level=False, request=request)
    return render(request, 'dojo/new_tool_type.html',
                  {'tform': tform})


@user_passes_test(lambda u: u.is_staff)
def edit_regulations(request, ttid):
    tool_type = Tool_Type.objects.get(pk=ttid)
    if request.method == 'POST':
        tform = ToolTypeForm(request.POST, instance=tool_type)
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Tool Type Configuration Successfully Updated.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('tool_type', ))
    else:
        tform = ToolTypeForm(instance=tool_type)
    add_breadcrumb(title="Edit Tool Type Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/edit_tool_type.html',
                  {
                      'tform': tform,
                  })




@user_passes_test(lambda u: u.is_staff)
def regulations(request):
     confs = Regulation.objects.all().order_by('name')
     add_breadcrumb(title="Regulations", top_level=not len(request.GET), request=request)
     return render(request,
                   'dojo/regulations.html',
                   {'confs': confs,
                    })
