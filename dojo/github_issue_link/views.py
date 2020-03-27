# Standard library imports
import json
import logging

# Third party imports
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.contrib.admin.utils import NestedObjects
from django.urls import reverse
from django.db import DEFAULT_DB_ALIAS
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import PermissionDenied
from github import Github
import requests

# Local application/library imports
from dojo.forms import GITHUBForm, DeleteGITHUBConfForm, ExpressGITHUBForm
from dojo.models import User, GITHUB_Conf, GITHUB_Issue, Notes, Risk_Acceptance
from dojo.utils import add_breadcrumb, get_system_setting, create_notification

logger = logging.getLogger(__name__)


@csrf_exempt
def webhook(request):
    return HttpResponse('')

@user_passes_test(lambda u: u.is_staff)
def express_new_github(request):
    return HttpResponse('')


@user_passes_test(lambda u: u.is_staff)
def new_github(request):
    if request.method == 'POST':
        jform = GITHUBForm(request.POST, instance=GITHUB_Conf())
        if jform.is_valid():
            try:
                api_key = jform.cleaned_data.get('api_key')
                
                # Try to connect to github with provided api key 
                g = Github(api_key)      
                user = g.get_user()
                logger.debug('Using user ' + user.login)

                new_j = jform.save(commit=False)
                new_j.api_key = api_key
                new_j.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Github Configuration Successfully Created.',
                                     extra_tags='alert-success')
                #create_notification(event='other',
                #                    title='New addition of JIRA URL %s' % jform.cleaned_data.get('url').rstrip('/'),
                #                    description='JIRA url "%s" was added by %s' %
                #                                (jform.cleaned_data.get('url').rstrip('/'), request.user),
                #                    url=request.build_absolute_uri(reverse('jira')),
                #                    )
                return HttpResponseRedirect(reverse('github', ))
            except Exception as info:
                print(info)
                messages.add_message(request,
                                     messages.ERROR,
                                     'Unable to authenticate on github.',
                                     extra_tags='alert-danger')
                return HttpResponseRedirect(reverse('github', ))
    else:
        jform = GITHUBForm()
        add_breadcrumb(title="New Github Configuration", top_level=False, request=request)
        return render(request, 'dojo/new_github.html',
                    {'jform': jform})


@user_passes_test(lambda u: u.is_staff)
def edit_github(request, jid):
    return HttpResponse('')


@user_passes_test(lambda u: u.is_staff)
def github(request):
    confs = GITHUB_Conf.objects.all()
    add_breadcrumb(title="Github List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/github.html',
                  {'confs': confs,
                   })


@user_passes_test(lambda u: u.is_staff)
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
                                     'Github Conf and relationships removed.',
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


