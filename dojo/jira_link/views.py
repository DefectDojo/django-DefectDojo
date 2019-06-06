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
from jira import JIRA

# Local application/library imports
from dojo.forms import JIRAForm, DeleteJIRAConfForm
from dojo.models import User, JIRA_Conf, JIRA_Issue, Notes
from dojo.utils import add_breadcrumb, get_system_setting

logger = logging.getLogger(__name__)


@csrf_exempt
def webhook(request):
    # Webhook shouldn't be active if jira isn't enabled
    if not get_system_setting('enable_jira'):
        raise PermissionDenied
    elif not get_system_setting('enable_jira_web_hook'):
        raise PermissionDenied

    if request.method == 'POST':
        parsed = json.loads(request.body)
        if 'issue' in list(parsed.keys()):
            jid = parsed['issue']['id']
            jissue = get_object_or_404(JIRA_Issue, jira_id=jid)
            if jissue.finding is not None:
                finding = jissue.finding
                resolved = True
                if parsed['issue']['fields']['resolution'] is None:
                    resolved = False
                if finding.active == resolved:
                    if finding.active:
                        now = timezone.now()
                        finding.active = False
                        finding.mitigated = now
                        finding.endpoints.clear()
                    else:
                        finding.active = True
                        finding.mitigated = None
                        finding.save()
                    finding.save()
            """
            if jissue.engagement is not None:
                eng = jissue.engagement
                if parsed['issue']['fields']['resolution'] != None:
                    eng.active = False
                    eng.status = 'Completed'
                    eng.save()
           """
        else:
            comment_text = parsed['comment']['body']
            commentor = parsed['comment']['updateAuthor']['displayName']
            jid = parsed['comment']['self'].split('/')[7]
            jissue = JIRA_Issue.objects.get(jira_id=jid)
            finding = jissue.finding
            new_note = Notes()
            new_note.entry = '(%s): %s' % (commentor, comment_text)
            new_note.author, created = User.objects.get_or_create(username='JIRA')
            new_note.save()
            finding.notes.add(new_note)
            finding.save()
    return HttpResponse('')


@user_passes_test(lambda u: u.is_staff)
def new_jira(request):
    if request.method == 'POST':
        jform = JIRAForm(request.POST, instance=JIRA_Conf())
        if jform.is_valid():
            try:
                jira_server = jform.cleaned_data.get('url').rstrip('/')
                jira_username = jform.cleaned_data.get('username')
                jira_password = jform.cleaned_data.get('password')

                # Instantiate JIRA instance for validating url, username and password
                JIRA(server=jira_server,
                     basic_auth=(jira_username, jira_password))

                new_j = jform.save(commit=False)
                new_j.url = jira_server
                new_j.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'JIRA Configuration Successfully Created.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('jira', ))
            except Exception:
                messages.add_message(request,
                                     messages.ERROR,
                                     'Unable to authenticate. Please check the URL, username, and password.',
                                     extra_tags='alert-danger')
    else:
        jform = JIRAForm()
        add_breadcrumb(title="New Jira Configuration", top_level=False, request=request)
    return render(request, 'dojo/new_jira.html',
                  {'jform': jform})


@user_passes_test(lambda u: u.is_staff)
def edit_jira(request, jid):
    jira = JIRA_Conf.objects.get(pk=jid)
    if request.method == 'POST':
        jform = JIRAForm(request.POST, instance=jira)
        if jform.is_valid():
            try:
                jira_server = jform.cleaned_data.get('url').rstrip('/')
                jira_username = jform.cleaned_data.get('username')
                jira_password = jform.cleaned_data.get('password')

                # Instantiate JIRA instance for validating url, username and password
                JIRA(server=jira_server,
                     basic_auth=(jira_username, jira_password))

                new_j = jform.save(commit=False)
                new_j.url = jira_server
                new_j.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'JIRA Configuration Successfully Created.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('jira', ))
            except Exception:
                messages.add_message(request,
                                     messages.ERROR,
                                     'Unable to authenticate. Please check the URL, username, and password.',
                                     extra_tags='alert-danger')
    else:
        jform = JIRAForm(instance=jira)
        add_breadcrumb(title="Edit JIRA Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/edit_jira.html',
                  {
                      'jform': jform,
                  })


@user_passes_test(lambda u: u.is_staff)
def delete_issue(request, find):
    j_issue = JIRA_Issue.objects.get(finding=find)
    jira_conf = find.jira_conf()
    jira = JIRA(server=jira_conf.url,
                basic_auth=(jira_conf.username,
                            jira_conf.password))
    issue = jira.issue(j_issue.jira_id)
    issue.delete()


@user_passes_test(lambda u: u.is_staff)
def jira(request):
    confs = JIRA_Conf.objects.all()
    add_breadcrumb(title="JIRA List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/jira.html',
                  {'confs': confs,
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_jira(request, tid):
    jira_instance = get_object_or_404(JIRA_Conf, pk=tid)
    # eng = test.engagement
    # TODO Make Form
    form = DeleteJIRAConfForm(instance=jira_instance)

    if request.method == 'POST':
        if 'id' in request.POST and str(jira_instance.id) == request.POST['id']:
            form = DeleteJIRAConfForm(request.POST, instance=jira_instance)
            if form.is_valid():
                jira_instance.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'JIRA Conf and relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('jira'))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([jira_instance])
    rels = collector.nested()

    add_breadcrumb(title="Delete", top_level=False, request=request)
    return render(request, 'dojo/delete_jira.html',
                  {'inst': jira_instance,
                   'form': form,
                   'rels': rels,
                   'deletable_objects': rels,
                   })
