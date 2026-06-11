import logging

from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.cicd_infrastructure.ui.forms import CICDInfrastructureForm
from dojo.models import CICDInfrastructure
from dojo.utils import add_breadcrumb

logger = logging.getLogger(__name__)


def cicd_infrastructure(request):
    confs = CICDInfrastructure.objects.all().order_by("name")
    add_breadcrumb(title=_("CI/CD Infrastructure List"), top_level=not len(request.GET), request=request)
    return render(request, "dojo/cicd_infrastructure.html", {"confs": confs})


def new_cicd_infrastructure(request):
    if request.method == "POST":
        form = CICDInfrastructureForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request, messages.SUCCESS,
                                 _("CI/CD Infrastructure successfully created."),
                                 extra_tags="alert-success")
            return HttpResponseRedirect(reverse("cicd_infrastructure"))
    else:
        form = CICDInfrastructureForm()
        add_breadcrumb(title=_("New CI/CD Infrastructure"), top_level=False, request=request)
    return render(request, "dojo/new_cicd_infrastructure.html", {"form": form})


def edit_cicd_infrastructure(request, ciid):
    conf = get_object_or_404(CICDInfrastructure, pk=ciid)
    if request.method == "POST":
        form = CICDInfrastructureForm(request.POST, instance=conf)
        if form.is_valid():
            form.save()
            messages.add_message(request, messages.SUCCESS,
                                 _("CI/CD Infrastructure successfully updated."),
                                 extra_tags="alert-success")
            return HttpResponseRedirect(reverse("cicd_infrastructure"))
    else:
        form = CICDInfrastructureForm(instance=conf)
    add_breadcrumb(title=_("Edit CI/CD Infrastructure"), top_level=False, request=request)
    return render(request, "dojo/edit_cicd_infrastructure.html", {"form": form, "conf": conf})


def delete_cicd_infrastructure(request, ciid):
    conf = get_object_or_404(CICDInfrastructure, pk=ciid)
    if request.method == "POST":
        conf.delete()
        messages.add_message(request, messages.SUCCESS,
                             _("CI/CD Infrastructure successfully deleted."),
                             extra_tags="alert-success")
        return HttpResponseRedirect(reverse("cicd_infrastructure"))
    add_breadcrumb(title=_("Delete CI/CD Infrastructure"), top_level=False, request=request)
    return render(request, "dojo/delete_cicd_infrastructure.html", {"conf": conf})
