# #dev envs
import logging

from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404

from dojo.filters import EnvironmentFilter
from dojo.forms import EnvironmentForm, DeleteEnvironmentForm
from dojo.models import Development_Environment
from dojo.utils import get_page_items, add_breadcrumb

logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_staff)
def environment(request):
    initial_queryset = Development_Environment.objects.all().order_by('name')
    name_words = [de.name for de in
                  initial_queryset]
    devs = EnvironmentFilter(request.GET, queryset=initial_queryset)
    dev_page = get_page_items(request, devs.qs, 25)
    add_breadcrumb(title="Environment List", top_level=True, request=request)
    return render(request, 'dojo/environment.html', {
        'name': 'Environment',
        'metric': False,
        'user': request.user,
        'devs': dev_page,
        'dts': devs,
        'name_words': name_words})


@user_passes_test(lambda u: u.is_staff)
def add_environment(request):
    form = EnvironmentForm()
    if request.method == 'POST':
        form = EnvironmentForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Environment added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('environment'))
    add_breadcrumb(title="Add Environment", top_level=False, request=request)
    return render(request, 'dojo/new_environment.html', {
        'name': 'Add Environment',
        'metric': False,
        'user': request.user,
        'form': form,
    })


@user_passes_test(lambda u: u.is_staff)
def edit_environment(request, deid):
    de = get_object_or_404(Development_Environment, pk=deid)
    form1 = EnvironmentForm(instance=de)
    form2 = DeleteEnvironmentForm(instance=de)
    if request.method == 'POST' and request.POST.get('edit_environment'):
        form1 = EnvironmentForm(request.POST, instance=de)
        if form1.is_valid():
            de = form1.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Environment updated successfully.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('environment'))
    if request.method == 'POST' and request.POST.get('delete_environment'):
        form2 = DeleteEnvironmentForm(request.POST, instance=de)
        if form2.is_valid():
            de.delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Environment deleted successfully.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('environment'))

    add_breadcrumb(title="Edit Environment", top_level=False, request=request)
    return render(request, 'dojo/edit_environment.html', {
        'name': 'Edit Environment',
        'metric': False,
        'user': request.user,
        'form1': form1,
        'de': de})
