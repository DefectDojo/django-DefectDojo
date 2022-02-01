# #  product
import logging

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from dojo.utils import add_breadcrumb
from dojo.forms import RegulationForm
from dojo.models import Regulation
from dojo.authorization.authorization_decorators import user_is_configuration_authorized
from dojo.authorization.authorization import user_has_configuration_permission_or_403


logger = logging.getLogger(__name__)


@user_is_configuration_authorized('dojo.add_regulation', 'superuser')
def new_regulation(request):
    if request.method == 'POST':
        tform = RegulationForm(request.POST, instance=Regulation())
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Regulation Successfully Created.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('regulations', ))
    else:
        tform = RegulationForm()
        add_breadcrumb(title="New regulation", top_level=False, request=request)
    return render(request, 'dojo/new_regulation.html',
                  {'form': tform})


@user_is_configuration_authorized('dojo.change_regulation', 'superuser')
def edit_regulations(request, ttid):
    regulation = Regulation.objects.get(pk=ttid)
    if request.method == 'POST' and request.POST.get('delete'):
        user_has_configuration_permission_or_403(request.user, 'dojo.delete_regulation', 'superuser')
        Regulation.objects.filter(pk=ttid).delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             'Regulation Deleted.',
                             extra_tags='alert-success')
        return HttpResponseRedirect(reverse('regulations', ))
    elif request.method == 'POST':
        tform = RegulationForm(request.POST, instance=regulation)
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Regulation Successfully Updated.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('regulations', ))
    else:
        tform = RegulationForm(instance=regulation)
    add_breadcrumb(title="Edit Regulation", top_level=False, request=request)

    return render(request,
                  'dojo/edit_regulation.html',
                  {
                      'tform': tform,
                  })


@login_required
def regulations(request):
    confs = Regulation.objects.all().order_by('name')
    add_breadcrumb(title="Regulations", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/regulations.html',
                  {'confs': confs,
                   })
