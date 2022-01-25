# Standard library imports
import json
import logging

# Third party imports
from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.urls import reverse
from django.db import DEFAULT_DB_ALIAS
from django.http import HttpResponseRedirect, HttpResponse, Http404, HttpResponseBadRequest
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import PermissionDenied
# Local application/library imports
from dojo.forms import JIRAForm, DeleteJIRAInstanceForm, ExpressJIRAForm
from dojo.models import User, JIRA_Instance, JIRA_Issue, Notes
from dojo.utils import add_breadcrumb, add_error_message_to_response, get_system_setting
from dojo.notifications.helper import create_notification
from django.views.decorators.http import require_POST
import dojo.jira_link.helper as jira_helper
from dojo.authorization.authorization_decorators import user_is_configuration_authorized

logger = logging.getLogger(__name__)


# for examples of incoming json, see the unit tests for the webhook: https://github.com/DefectDojo/django-DefectDojo/blob/master/unittests/test_jira_webhook.py
# or the officials docs (which are not always clear): https://developer.atlassian.com/server/jira/platform/webhooks/
@csrf_exempt
@require_POST
def webhook(request, secret=None):
    if not get_system_setting('enable_jira'):
        logger.debug('ignoring incoming webhook as JIRA is disabled.')
        raise Http404('JIRA disabled')
    elif not get_system_setting('enable_jira_web_hook'):
        logger.debug('ignoring incoming webhook as JIRA Webhook is disabled.')
        raise Http404('JIRA Webhook disabled')
    elif not get_system_setting('disable_jira_webhook_secret'):
        if not get_system_setting('jira_webhook_secret'):
            logger.warning('ignoring incoming webhook as JIRA Webhook secret is empty in Defect Dojo system settings.')
            raise PermissionDenied('JIRA Webhook secret cannot be empty')
        if secret != get_system_setting('jira_webhook_secret'):
            logger.warning('invalid secret provided to JIRA Webhook')
            raise PermissionDenied('invalid or no secret provided to JIRA Webhook')

    # if webhook secret is disabled in system_settings, we ignore the incoming secret, even if it doesn't match

    # example json bodies at the end of this file

    if request.content_type != 'application/json':
        return HttpResponseBadRequest("only application/json supported")

    if request.method == 'POST':
        try:
            parsed = json.loads(request.body.decode('utf-8'))
            if parsed.get('webhookEvent') == 'jira:issue_updated':
                # xml examples at the end of file
                jid = parsed['issue']['id']
                jissue = get_object_or_404(JIRA_Issue, jira_id=jid)

                findings = None
                if jissue.finding:
                    logging.info("Received issue update for {} for finding {}".format(jissue.jira_key, jissue.finding.id))
                    findings = [jissue.finding]
                elif jissue.finding_group:
                    logging.info("Received issue update for {} for finding group {}".format(jissue.jira_key, jissue.finding_group))
                    findings = jissue.finding_group.findings.all()
                elif jissue.engagement:
                    # if parsed['issue']['fields']['resolution'] != None:
                    #     eng.active = False
                    #     eng.status = 'Completed'
                    #     eng.save()
                    return HttpResponse('Update for engagement ignored')
                else:
                    logging.info("Received issue update for {} for unknown object".format(jissue.jira_key))
                    raise Http404('No finding, finding_group or engagement found for JIRA issue {}'.format(jissue.jira_key))

                assignee = parsed['issue']['fields'].get('assignee')
                assignee_name = assignee['name'] if assignee else None

                resolution = parsed['issue']['fields']['resolution']

                #         "resolution":{
                #             "self":"http://www.testjira.com/rest/api/2/resolution/11",
                #             "id":"11",
                #             "description":"Cancelled by the customer.",
                #             "name":"Cancelled"
                #         },

                # or
                #         "resolution": null

                # or
                #         "resolution": "None"

                resolution = resolution if resolution and resolution != "None" else None
                resolution_id = resolution['id'] if resolution else None
                resolution_name = resolution['name'] if resolution else None
                jira_now = parse_datetime(parsed['issue']['fields']['updated'])

                if findings:
                    for finding in findings:
                        jira_helper.process_resolution_from_jira(finding, resolution_id, resolution_name, assignee_name, jira_now, jissue)

            if parsed.get('webhookEvent') == 'comment_created':
                """
                    example incoming requests from JIRA Server 8.14.0
                    {
                    "timestamp":1610269967824,
                    "webhookEvent":"comment_created",
                    "comment":{
                        "self":"https://jira.host.com/rest/api/2/issue/115254/comment/466578",
                        "id":"466578",
                        "author":{
                            "self":"https://jira.host.com/rest/api/2/user?username=defect.dojo",
                            "name":"defect.dojo",
                            "key":"defect.dojo", # seems to be only present on JIRA Server, not on Cloud
                            "avatarUrls":{
                                "48x48":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=48",
                                "24x24":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=24",
                                "16x16":"https://www.gravatar.com/avatar9637bfb970eff6176357df615f548f1c?d=mm&s=16",
                                "32x32":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=32"
                            },
                            "displayName":"Defect Dojo",
                            "active":true,
                            "timeZone":"Europe/Amsterdam"
                        },
                        "body":"(Valentijn Scholten):test4",
                        "updateAuthor":{
                            "self":"https://jira.host.com/rest/api/2/user?username=defect.dojo",
                            "name":"defect.dojo",
                            "key":"defect.dojo",
                            "avatarUrls":{
                                "48x48":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=48",
                                "24x24""https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=24",
                                "16x16":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=16",
                                "32x32":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=32"
                            },
                            "displayName":"Defect Dojo",
                            "active":true,
                            "timeZone":"Europe/Amsterdam"
                        },
                        "created":"2021-01-10T10:12:47.824+0100",
                        "updated":"2021-01-10T10:12:47.824+0100"
                    }
                    }
                """

                comment_text = parsed['comment']['body']
                commentor = ''
                if 'name' in parsed['comment']['updateAuthor']:
                    commentor = parsed['comment']['updateAuthor']['name']
                elif 'emailAddress' in parsed['comment']['updateAuthor']:
                    commentor = parsed['comment']['updateAuthor']['emailAddress']
                else:
                    logger.debug('Could not find the author of this jira comment!')
                commentor_display_name = parsed['comment']['updateAuthor']['displayName']
                # example: body['comment']['self'] = "http://www.testjira.com/jira_under_a_path/rest/api/2/issue/666/comment/456843"
                jid = parsed['comment']['self'].split('/')[-3]
                jissue = get_object_or_404(JIRA_Issue, jira_id=jid)
                logging.info("Received issue comment for {}".format(jissue.jira_key))
                logger.debug('jissue: %s', vars(jissue))

                jira_usernames = JIRA_Instance.objects.values_list('username', flat=True)
                for jira_userid in jira_usernames:
                    # logger.debug('incoming username: %s jira config username: %s', commentor.lower(), jira_userid.lower())
                    if jira_userid.lower() == commentor.lower():
                        logger.debug('skipping incoming JIRA comment as the user id of the comment in JIRA (%s) matches the JIRA username in DefectDojo (%s)', commentor.lower(), jira_userid.lower())
                        return HttpResponse('')
                        break

                findings = None
                if jissue.finding:
                    findings = [jissue.finding]
                    create_notification(event='other', title='JIRA incoming comment - %s' % (jissue.finding), finding=jissue.finding, url=reverse("view_finding", args=(jissue.finding.id, )), icon='check')
                elif jissue.finding_group:
                    findings = [jissue.finding_group.findings.all()]
                    create_notification(event='other', title='JIRA incoming comment - %s' % (jissue.finding), finding=jissue.finding, url=reverse("view_finding_group", args=(jissue.finding_group.id, )), icon='check')
                elif jissue.engagement:
                    return HttpResponse('Comment for engagement ignored')
                else:
                    raise Http404('No finding or engagement found for JIRA issue {}'.format(jissue.jira_key))

                for finding in findings:
                    # logger.debug('finding: %s', vars(jissue.finding))
                    new_note = Notes()
                    new_note.entry = '(%s (%s)): %s' % (commentor_display_name, commentor, comment_text)
                    new_note.author, created = User.objects.get_or_create(username='JIRA')
                    new_note.save()
                    finding.notes.add(new_note)
                    finding.jira_issue.jira_change = timezone.now()
                    finding.jira_issue.save()
                    finding.save()

            if parsed.get('webhookEvent') not in ['comment_created', 'jira:issue_updated']:
                logger.info('Unrecognized JIRA webhook event received: {}'.format(parsed.get('webhookEvent')))
        except Exception as e:
            if isinstance(e, Http404):
                logger.warning('404 error processing JIRA webhook')
            else:
                logger.exception(e)

            try:
                logger.debug('jira_webhook_body_parsed:')
                logger.debug(json.dumps(parsed, indent=4))
            except:
                logger.debug('jira_webhook_body:')
                logger.debug(request.body.decode('utf-8'))

            # reraise to make sure we don't silently swallow things
            raise
    return HttpResponse('')


def get_custom_field(jira, label):
    url = jira._options["server"].strip('/') + '/rest/api/2/field'
    response = jira._session.get(url).json()
    for node in response:
        if label in node['clauseNames']:
            field = int(node['schema']['customId'])
            break

    return field


@user_is_configuration_authorized('dojo.add_jira_instance', 'superuser')
def express_new_jira(request):
    if request.method == 'POST':
        jform = ExpressJIRAForm(request.POST, instance=JIRA_Instance())
        if jform.is_valid():
            jira_server = jform.cleaned_data.get('url').rstrip('/')
            jira_username = jform.cleaned_data.get('username')
            jira_password = jform.cleaned_data.get('password')

            try:
                jira = jira_helper.get_jira_connection_raw(jira_server, jira_username, jira_password)
            except Exception as e:
                logger.exception(e)  # already logged in jira_helper
                messages.add_message(request,
                                    messages.ERROR,
                                    'Unable to authenticate. Please check credentials.',
                                    extra_tags='alert-danger')
                return render(request, 'dojo/express_new_jira.html',
                                        {'jform': jform})
            # authentication successful
            # Get the open and close keys
            try:
                issue_id = jform.cleaned_data.get('issue_key')
                key_url = jira_server.strip('/') + '/rest/api/latest/issue/' + issue_id + '/transitions?expand=transitions.fields'
                response = jira._session.get(key_url).json()
                logger.debug('Retrieved JIRA issue succesfully')
                open_key = close_key = None
                for node in response['transitions']:
                    if node['to']['statusCategory']['name'] == 'To Do':
                        open_key = int(node['id']) if not open_key else open_key
                    if node['to']['statusCategory']['name'] == 'Done':
                        close_key = int(node['id']) if not close_key else close_key
            except Exception as e:
                logger.exception(e)  # already logged in jira_helper
                messages.add_message(request,
                                    messages.ERROR,
                                    'Unable to find Open/Close ID\'s (invalid issue key specified?). They will need to be found manually',
                                    extra_tags='alert-danger')
                return render(request, 'dojo/new_jira.html',
                                        {'jform': jform})
            # Get the epic id name
            try:
                epic_name = get_custom_field(jira, 'Epic Name')
            except Exception as e:
                logger.exception(e)  # already logged in jira_helper
                messages.add_message(request,
                                    messages.ERROR,
                                    'Unable to find Epic Name. It will need to be found manually',
                                    extra_tags='alert-danger')
                return render(request, 'dojo/new_jira.html',
                                        {'jform': jform})

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
    else:
        jform = ExpressJIRAForm()
        add_breadcrumb(title="New Jira Configuration (Express)", top_level=False, request=request)
    return render(request, 'dojo/express_new_jira.html',
                  {'jform': jform})


@user_is_configuration_authorized('dojo.add_jira_instance', 'superuser')
def new_jira(request):
    if request.method == 'POST':
        jform = JIRAForm(request.POST, instance=JIRA_Instance())
        if jform.is_valid():
            jira_server = jform.cleaned_data.get('url').rstrip('/')
            jira_username = jform.cleaned_data.get('username')
            jira_password = jform.cleaned_data.get('password')

            logger.debug('calling get_jira_connection_raw')
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
            logger.error('jform.errors: %s', jform.errors)
    else:
        jform = JIRAForm()
        add_breadcrumb(title="New Jira Configuration", top_level=False, request=request)
    return render(request, 'dojo/new_jira.html',
                  {'jform': jform})


@user_is_configuration_authorized('dojo.change_jira_instance', 'superuser')
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


@user_is_configuration_authorized('dojo.view_jira_instance', 'superuser')
def jira(request):
    jira_instances = JIRA_Instance.objects.all()
    add_breadcrumb(title="JIRA List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/jira.html',
                  {'jira_instances': jira_instances,
                   })


@user_is_configuration_authorized('dojo.delete_jira_instance', 'superuser')
def delete_jira(request, tid):
    jira_instance = get_object_or_404(JIRA_Instance, pk=tid)
    # eng = test.engagement
    # TODO Make Form
    form = DeleteJIRAInstanceForm(instance=jira_instance)

    if request.method == 'POST':
        if 'id' in request.POST and str(jira_instance.id) == request.POST['id']:
            form = DeleteJIRAInstanceForm(request.POST, instance=jira_instance)
            if form.is_valid():
                try:
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
                except Exception as e:
                    add_error_message_to_response('Unable to delete JIRA Instance, probably because it is used by JIRA Issues: %s' % str(e))

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
