# Standard library imports
import logging

# Third party imports
from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.urls import reverse
from django.db import DEFAULT_DB_ALIAS
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from github import Github

# Local application/library imports
from dojo.forms import GITHUBForm, DeleteGITHUBConfForm
from dojo.models import GITHUB_Conf
from dojo.utils import add_breadcrumb
from dojo.authorization.authorization_decorators import user_is_configuration_authorized

logger = logging.getLogger(__name__)


@csrf_exempt
def webhook(request):
    return HttpResponse('')


@user_is_configuration_authorized('dojo.add_github_conf', 'superuser')
def new_github(request):
    if request.method == 'POST':
        gform = GITHUBForm(request.POST, instance=GITHUB_Conf())
        if gform.is_valid():
            try:
                api_key = gform.cleaned_data.get('api_key')
                g = Github(api_key)
                user = g.get_user()
                logger.debug('Using user ' + user.login)

                new_j = gform.save(commit=False)
                new_j.api_key = api_key
                new_j.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'GitHub Configuration Successfully Created.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('github', ))
            except Exception as info:
                logger.error(info)
                messages.add_message(request,
                                     messages.ERROR,
                                     'Unable to authenticate on GitHub.',
                                     extra_tags='alert-danger')
                return HttpResponseRedirect(reverse('github', ))
    else:
        gform = GITHUBForm()
        add_breadcrumb(title="New GitHub Configuration", top_level=False, request=request)
        return render(request, 'dojo/new_github.html',
                    {'gform': gform})


@user_is_configuration_authorized('dojo.view_github_conf', 'superuser')
def github(request):
    confs = GITHUB_Conf.objects.all()
    add_breadcrumb(title="GitHub List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/github.html',
                  {'confs': confs,
                   })


@user_is_configuration_authorized('dojo.delete_github_conf', 'superuser')
def delete_github(request, tid):
    github_instance = get_object_or_404(GITHUB_Conf, pk=tid)
    # eng = test.engagement
    # TODO Make Form
    form = DeleteGITHUBConfForm(instance=github_instance)

    if request.method == 'POST':
        if 'id' in request.POST and str(github_instance.id) == request.POST['id']:
            form = DeleteGITHUBConfForm(request.POST, instance=github_instance)
            if form.is_valid():
                github_instance.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'GitHub Conf and relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('github'))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([github_instance])
    rels = collector.nested()

    add_breadcrumb(title="Delete", top_level=False, request=request)
    return render(request, 'dojo/delete_github.html',
                  {'inst': github_instance,
                   'form': form,
                   'rels': rels,
                   'deletable_objects': rels,
                   })
