# #  product
import logging

from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

from dojo.authorization.authorization_decorators import user_is_configuration_authorized
from dojo.forms import SLAConfigForm
from dojo.models import SLA_Configuration, System_Settings
from dojo.utils import add_breadcrumb

logger = logging.getLogger(__name__)


@user_is_configuration_authorized('dojo.add_sla_configuration', 'superuser')
def new_sla_config(request):
    if request.method == 'POST':
        tform = SLAConfigForm(request.POST, instance=SLA_Configuration())
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'SLA configuration Successfully Created.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('sla_config', ))
    else:
        tform = SLAConfigForm()
        add_breadcrumb(title="New SLA configuration", top_level=False, request=request)
    return render(request, 'dojo/new_sla_config.html',
                  {'form': tform})


@user_is_configuration_authorized('dojo.change_sla_configuration', 'superuser')
def edit_sla_config(request, ttid):
    sla_config = SLA_Configuration.objects.get(pk=ttid)
    if request.method == 'POST':
        tform = SLAConfigForm(request.POST, instance=sla_config)
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'SLA configuration successfully updated.',
                                 extra_tags='alert-success')
            tform.save(commit=True)
    else:
        tform = SLAConfigForm(instance=sla_config)
    add_breadcrumb(title="Edit SLA Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/edit_sla_config.html',
                  {
                      'tform': tform,
                  })


@user_is_configuration_authorized('dojo.view_sla_configuration', 'superuser')
def sla_config(request):
    settings = System_Settings.objects.all()

    confs = SLA_Configuration.objects.all().order_by('name')
    add_breadcrumb(title="SLA Configurations", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/sla_config.html',
                  {'confs': confs,
                   'settings': settings
                   })
