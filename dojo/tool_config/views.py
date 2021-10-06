# #  product
import logging

from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from dojo.models import Tool_Configuration, Tool_Type
from dojo.utils import dojo_crypto_encrypt, prepare_for_view
from dojo.utils import add_breadcrumb
from dojo.forms import ToolConfigForm
from dojo.tools.cobalt_api.api_client import CobaltAPI
from dojo.tools.sonarqube_api.api_client import SonarQubeAPI

logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_superuser)
def new_tool_config(request):
    if request.method == 'POST':
        tform = ToolConfigForm(request.POST)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            try:
                tool_type_qs_sonarqube = Tool_Type.objects.filter(name='SonarQube')
                if form_copy.tool_type in tool_type_qs_sonarqube:
                    sq = SonarQubeAPI(form_copy)
                    project_count = sq.test_connection()  # if connection is not successful, this call raise exception
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         'SonarQube connection successful. You have access to {} projects'.format(project_count),
                                         extra_tags='alert-success')
                tool_type_qs_cobaltio = Tool_Type.objects.filter(name='Cobalt.io')
                if form_copy.tool_type in tool_type_qs_cobaltio:
                    cobalt = CobaltAPI(form_copy)
                    org = cobalt.test_connection()  # if connection is not successful, this call raise exception
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         'Cobalt.io connection successful. You have access to the "{}" org'.format(org["resource"]["name"]),
                                         extra_tags='alert-success')
                form_copy.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Tool Configuration Successfully Updated.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('tool_config', ))
            except Exception as e:
                messages.add_message(request,
                                     messages.ERROR,
                                     str(e),
                                     extra_tags='alert-danger')
    else:
        tform = ToolConfigForm()
        add_breadcrumb(title="New Tool Configuration", top_level=False, request=request)
    return render(request, 'dojo/new_tool_config.html',
                  {'tform': tform})


@user_passes_test(lambda u: u.is_superuser)
def edit_tool_config(request, ttid):
    tool_config = Tool_Configuration.objects.get(pk=ttid)
    if request.method == 'POST':
        tform = ToolConfigForm(request.POST, instance=tool_config)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            form_copy.password = dojo_crypto_encrypt(tform.cleaned_data['password'])
            form_copy.ssh = dojo_crypto_encrypt(tform.cleaned_data['ssh'])
            try:
                tool_type_qs_sonarqube = Tool_Type.objects.filter(name='SonarQube')
                if form_copy.tool_type in tool_type_qs_sonarqube:
                    sq = SonarQubeAPI(form_copy)
                    project_count = sq.test_connection()  # if connection is not successful, this call raise exception
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         'SonarQube connection successful. You have access to {} projects'.format(project_count),
                                         extra_tags='alert-success')
                tool_type_qs_cobaltio = Tool_Type.objects.filter(name='Cobalt.io')
                if form_copy.tool_type in tool_type_qs_cobaltio:
                    cobalt = CobaltAPI(form_copy)
                    org = cobalt.test_connection()  # if connection is not successful, this call raise exception
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         'Cobalt.io connection successful. You have access to the "{}" org'.format(org["resource"]["name"]),
                                         extra_tags='alert-success')
                form_copy.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Tool Configuration Successfully Updated.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('tool_config', ))
            except Exception as e:
                messages.add_message(request,
                                     messages.ERROR,
                                     str(e),
                                     extra_tags='alert-danger')
    else:
        tool_config.password = prepare_for_view(tool_config.password)
        tool_config.ssh = prepare_for_view(tool_config.ssh)
        tform = ToolConfigForm(instance=tool_config)
    add_breadcrumb(title="Edit Tool Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/edit_tool_config.html',
                  {
                      'tform': tform,
                  })


@user_passes_test(lambda u: u.is_superuser)
def tool_config(request):
    confs = Tool_Configuration.objects.all().order_by('name')
    add_breadcrumb(title="Tool Configuration List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/tool_config.html',
                  {'confs': confs,
                   })
