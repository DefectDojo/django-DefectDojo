# #  product
import logging

from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from dojo.utils import add_breadcrumb
from dojo.forms import ToolTypeForm
from dojo.models import Tool_Type, JIRA_Issue
from jira import JIRA


logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_staff)
def new_tool_type(request):
    if request.method == 'POST':
        tform = ToolTypeForm(request.POST, instance=Tool_Type())
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Tool Type Configuration Successfully Created.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('tool_type', ))
    else:
        tform = ToolTypeForm()
        add_breadcrumb(title="New Tool Type Configuration", top_level=False, request=request)
    return render(request, 'dojo/new_tool_type.html',
                  {'tform': tform})


@user_passes_test(lambda u: u.is_staff)
def edit_tool_type(request, ttid):
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
def delete_issue(request, find):
    j_issue = JIRA_Issue.objects.get(finding=find)
    jira = JIRA(server=Tool_Type.url,
                basic_auth=(Tool_Type.username, Tool_Type.password),
                verify=settings.JIRA_SSL_VERIFY)
    issue = jira.issue(j_issue.jira_id)
    issue.delete()


@user_passes_test(lambda u: u.is_staff)
def tool_type(request):
    confs = Tool_Type.objects.all().order_by('name')
    add_breadcrumb(title="Tool Type List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/tool_type.html',
                  {'confs': confs,
                   })
