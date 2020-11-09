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
import requests

# Local application/library imports
from dojo.forms import JIRAForm, DeleteJIRAInstanceForm, ExpressJIRAForm
from dojo.models import User, JIRA_Instance, JIRA_Issue, Notes, Risk_Acceptance
from dojo.utils import add_breadcrumb, get_system_setting
from dojo.notifications.helper import create_notification
from django.views.decorators.http import require_POST
import dojo.jira_link.helper as jira_helper

logger = logging.getLogger(__name__)


@csrf_exempt
@require_POST
def webhook(request, secret=None):
    if not get_system_setting('enable_jira'):
        logger.debug('ignoring incoming webhook as JIRA is disabled.')
        raise PermissionDenied('JIRA disable')
    elif not get_system_setting('enable_jira_web_hook'):
        logger.debug('ignoring incoming webhook as JIRA Webhook is disabled.')
        raise PermissionDenied('JIRA Webhook disabled')
    elif not get_system_setting('disable_jira_webhook_secret'):
        if not get_system_setting('jira_webhook_secret'):
            logger.warning('ignoring incoming webhook as JIRA Webhook secret is empty in Defect Dojo system settings.')
            raise PermissionDenied('JIRA Webhook secret cannot be empty')
        if secret != get_system_setting('jira_webhook_secret'):
            logger.warning('invalid secret provided to JIRA Webhook')
            raise PermissionDenied('invalid or no secret provided to JIRA Webhook')

    # if webhook secret is disabled in system_settings, we ignore the incoming secret, even if it doesn't match

    if request.method == 'POST':
        parsed = json.loads(request.body.decode('utf-8'))
        if parsed.get('webhookEvent') == 'jira:issue_updated':
            jid = parsed['issue']['id']
            jissue = get_object_or_404(JIRA_Issue, jira_id=jid)
            if jissue.finding is not None:
                finding = jissue.finding
                jira_instance = jira_helper.get_jira_instance(finding)
                resolved = True
                resolution = parsed['issue']['fields']['resolution']
                if resolution is None:
                    resolved = False
                if finding.active == resolved:
                    if finding.active:
                        if jira_instance and resolution['name'] in jira_instance.accepted_resolutions:
                            finding.active = False
                            finding.mitigated = None
                            finding.is_Mitigated = False
                            finding.false_p = False
                            assignee = parsed['issue']['fields'].get('assignee')
                            assignee_name = assignee['name'] if assignee else None
                            Risk_Acceptance.objects.create(
                                accepted_by=assignee_name,
                                reporter=finding.reporter,
                            ).accepted_findings.set([finding])
                        elif jira_instance and resolution['name'] in jira_instance.false_positive_resolutions:
                            finding.active = False
                            finding.verified = False
                            finding.mitigated = None
                            finding.is_Mitigated = False
                            finding.false_p = True
                            finding.remove_from_any_risk_acceptance()
                        else:
                            # Mitigated by default as before
                            now = timezone.now()
                            finding.active = False
                            finding.mitigated = now
                            finding.is_Mitigated = True
                            finding.endpoints.clear()
                            finding.false_p = False
                            finding.remove_from_any_risk_acceptance()
                    else:
                        # Reopen / Open Jira issue
                        finding.active = True
                        finding.mitigated = None
                        finding.is_Mitigated = False
                        finding.false_p = False
                        finding.remove_from_any_risk_acceptance()

                    finding.jira_issue.jira_change = timezone.now()
                    finding.jira_issue.save()
                    finding.save()
            """
            if jissue.engagement is not None:
                eng = jissue.engagement
                if parsed['issue']['fields']['resolution'] != None:
                    eng.active = False
                    eng.status = 'Completed'
                    eng.save()
           """
        if parsed.get('webhookEvent') == 'comment_created':
            comment_text = parsed['comment']['body']
            commentor = parsed['comment']['updateAuthor']['displayName']
            jid = parsed['comment']['self'].split('/')[7]
            jissue = JIRA_Issue.objects.get(jira_id=jid)
            jira_usernames = JIRA_Instance.objects.values_list('username', flat=True)
            for jira_userid in jira_usernames:
                if jira_userid.lower() in commentor.lower():
                    return HttpResponse('')
                    break
            finding = jissue.finding
            new_note = Notes()
            new_note.entry = '(%s): %s' % (commentor, comment_text)
            new_note.author, created = User.objects.get_or_create(username='JIRA')
            new_note.save()
            finding.notes.add(new_note)
            finding.jira_issue.jira_change = timezone.now()
            finding.jira_issue.save()
            finding.save()
            create_notification(event='other', title='JIRA Update - %s' % (jissue.finding), url=reverse("view_finding", args=(jissue.id,)), icon='check')

        if parsed.get('webhookEvent') not in ['comment_created', 'jira:issue_updated']:
            logger.info('Unrecognized JIRA webhook event received: {}'.format(parsed.get('webhookEvent')))
    return HttpResponse('')


@user_passes_test(lambda u: u.is_staff)
def express_new_jira(request):
    if request.method == 'POST':
        jform = ExpressJIRAForm(request.POST, instance=JIRA_Instance())
        if jform.is_valid():
            try:
                jira_server = jform.cleaned_data.get('url').rstrip('/')
                jira_username = jform.cleaned_data.get('username')
                jira_password = jform.cleaned_data.get('password')

                try:
                    jira = jira_helper.get_jira_connection_raw(jira_server, jira_username, jira_password)
                except Exception as e:
                    logger.exception(e)  # already logged in jira_helper
                    return render(request, 'dojo/express_new_jira.html',
                                            {'jform': jform})
                # authentication successful
                # Get the open and close keys
                issue_id = jform.cleaned_data.get('issue_key')
                key_url = jira_server + '/rest/api/latest/issue/' + issue_id + '/transitions?expand=transitions.fields'
                data = json.loads(requests.get(key_url, auth=(jira_username, jira_password)).text)
                for node in data['transitions']:
                    if node['to']['name'] == 'To Do':
                        open_key = int(node['to']['id'])
                    if node['to']['name'] == 'Done':
                        close_key = int(node['to']['id'])
                # Get the epic id name
                key_url = jira_server + '/rest/api/2/field'
                data = json.loads(requests.get(key_url, auth=(jira_username, jira_password)).text)
                for node in data:
                    if 'Epic Name' in node['clauseNames']:
                        epic_name = int(node['clauseNames'][0][3:-1])
                        break

                jira_instance = JIRA_Instance(username=jira_username,
                                        password=jira_password,
                                        url=jira_server,
                                        configuration_name=jform.cleaned_data.get('configuration_name'),
                                        info_mapping_severity='Lowest',
                                        low_mapping_severity='Low',
                                        medium_mapping_severity='Medium',
                                        high_mapping_severity='High',
                                        critical_mapping_severity='Highest',
                                        epic_name_id=epic_name,
                                        open_status_key=open_key,
                                        close_status_key=close_key,
                                        finding_text='',
                                        default_issue_type=jform.cleaned_data.get('default_issue_type'))
                jira_instance.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'JIRA Configuration Successfully Created.',
                                     extra_tags='alert-success')
                create_notification(event='other',
                                    title='New addition of JIRA: %s' % jform.cleaned_data.get('configuration_name'),
                                    description='JIRA "%s" was added by %s' %
                                                (jform.cleaned_data.get('configuration_name'), request.user),
                                    url=request.build_absolute_uri(reverse('jira')),
                                    )
                return HttpResponseRedirect(reverse('jira', ))
            except:
                messages.add_message(request,
                                     messages.ERROR,
                                     'Unable to query other required fields. They must be entered manually.',
                                     extra_tags='alert-danger')
                return HttpResponseRedirect(reverse('add_jira', ))
            return render(request, 'dojo/express_new_jira.html',
                {'jform': jform})
    else:
        jform = ExpressJIRAForm()
        add_breadcrumb(title="New Jira Configuration (Express)", top_level=False, request=request)
    return render(request, 'dojo/express_new_jira.html',
                  {'jform': jform})


@user_passes_test(lambda u: u.is_staff)
def new_jira(request):
    if request.method == 'POST':
        jform = JIRAForm(request.POST, instance=JIRA_Instance())
        if jform.is_valid():
            jira_server = jform.cleaned_data.get('url').rstrip('/')
            jira_username = jform.cleaned_data.get('username')
            jira_password = jform.cleaned_data.get('password')

            jira = jira_helper.get_jira_connection_raw(jira_server, jira_username, jira_password)

            new_j = jform.save(commit=False)
            new_j.url = jira_server
            new_j.save()
            messages.add_message(request,
                                    messages.SUCCESS,
                                    'JIRA Configuration Successfully Created.',
                                    extra_tags='alert-success')
            create_notification(event='other',
                                title='New addition of JIRA: %s' % jform.cleaned_data.get('configuration_name'),
                                description='JIRA "%s" was added by %s' %
                                            (jform.cleaned_data.get('configuration_name'), request.user),
                                url=request.build_absolute_uri(reverse('jira')),
                                )
            return HttpResponseRedirect(reverse('jira', ))
    else:
        jform = JIRAForm()
        add_breadcrumb(title="New Jira Configuration", top_level=False, request=request)
    return render(request, 'dojo/new_jira.html',
                  {'jform': jform})


@user_passes_test(lambda u: u.is_staff)
def edit_jira(request, jid):
    jira = JIRA_Instance.objects.get(pk=jid)
    jira_password_from_db = jira.password
    if request.method == 'POST':
        jform = JIRAForm(request.POST, instance=jira)
        if jform.is_valid():
            jira_server = jform.cleaned_data.get('url').rstrip('/')
            jira_username = jform.cleaned_data.get('username')

            if jform.cleaned_data.get('password'):
                jira_password = jform.cleaned_data.get('password')
            else:
                # on edit the password is optional
                jira_password = jira_password_from_db

            jira = jira_helper.get_jira_connection_raw(jira_server, jira_username, jira_password)

            new_j = jform.save(commit=False)
            new_j.url = jira_server
            # on edit the password is optional
            new_j.password = jira_password
            new_j.save()
            messages.add_message(request,
                                    messages.SUCCESS,
                                    'JIRA Configuration Successfully Saved.',
                                    extra_tags='alert-success')
            create_notification(event='other',
                                title='Edit of JIRA: %s' % jform.cleaned_data.get('configuration_name'),
                                description='JIRA "%s" was edited by %s' %
                                            (jform.cleaned_data.get('configuration_name'), request.user),
                                url=request.build_absolute_uri(reverse('jira')),
                                )
            return HttpResponseRedirect(reverse('jira', ))

    else:
        jform = JIRAForm(instance=jira)
        add_breadcrumb(title="Edit JIRA Configuration", top_level=False, request=request)

    return render(request,
                  'dojo/edit_jira.html',
                  {
                      'jform': jform,
                  })


@user_passes_test(lambda u: u.is_staff)
def jira(request):
    jira_instances = JIRA_Instance.objects.all()
    add_breadcrumb(title="JIRA List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/jira.html',
                  {'jira_instances': jira_instances,
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_jira(request, tid):
    jira_instance = get_object_or_404(JIRA_Instance, pk=tid)
    # eng = test.engagement
    # TODO Make Form
    form = DeleteJIRAInstanceForm(instance=jira_instance)

    if request.method == 'POST':
        if 'id' in request.POST and str(jira_instance.id) == request.POST['id']:
            form = DeleteJIRAInstanceForm(request.POST, instance=jira_instance)
            if form.is_valid():
                jira_instance.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'JIRA Conf and relationships removed.',
                                     extra_tags='alert-success')
                create_notification(event='other',
                                    title='Deletion of JIRA: %s' % jira_instance.configuration_name,
                                    description='JIRA "%s" was deleted by %s' % (jira_instance.configuration_name, request.user),
                                    url=request.build_absolute_uri(reverse('jira')),
                                    )
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
