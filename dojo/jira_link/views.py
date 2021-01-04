# Standard library imports
import json
import logging

# Third party imports
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.contrib.admin.utils import NestedObjects
from django.urls import reverse
from django.db import DEFAULT_DB_ALIAS
from django.http import HttpResponseRedirect, HttpResponse, Http404, HttpResponseBadRequest
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
        # logger.debug('jira_webhook_body:')
        # logger.debug(request.body.decode('utf-8'))
        parsed = json.loads(request.body.decode('utf-8'))
        if parsed.get('webhookEvent') == 'jira:issue_updated':
            jid = parsed['issue']['id']
            jissue = get_object_or_404(JIRA_Issue, jira_id=jid)
            if jissue.finding:
                finding = jissue.finding
                jira_instance = jira_helper.get_jira_instance(finding)
                resolved = True
                resolution = parsed['issue']['fields']['resolution']

                #         "resolution":{
                #             "self":"http://www.testjira.com/rest/api/2/resolution/11",
                #             "id":"11",
                #             "description":"Cancelled by the customer.",
                #             "name":"Cancelled"
                #         },

                # or
                #         "resolution": null

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
                                owner=finding.reporter,
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
            elif jissue.engagement:
                # if parsed['issue']['fields']['resolution'] != None:
                #     eng.active = False
                #     eng.status = 'Completed'
                #     eng.save()
                return HttpResponse('Update for engagement ignored')
            else:
                raise Http404('No finding or engagement found for this JIRA issue')

        if parsed.get('webhookEvent') == 'comment_created':
            comment_text = parsed['comment']['body']
            commentor = parsed['comment']['updateAuthor']['displayName']
            # example: body['comment']['self'] = "http://www.testjira.com/jira_under_a_path/rest/api/2/issue/666/comment/456843"
            jid = parsed['comment']['self'].split('/')[-3]
            jissue = get_object_or_404(JIRA_Issue, jira_id=jid)
            logger.debug('jissue: %s', vars(jissue))
            if jissue.finding:
                logger.debug('finding: %s', vars(jissue.finding))
                jira_usernames = JIRA_Instance.objects.values_list('username', flat=True)
                for jira_userid in jira_usernames:
                    if jira_userid.lower() in commentor.lower():
                        logger.info('skipping incoming JIRA comment as the user id of the comment mathces the JIRA user in Defect Dojo')
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
                create_notification(event='other', title='JIRA incoming comment - %s' % (jissue.finding), url=reverse("view_finding", args=(jissue.finding.id, )), icon='check')
            elif jissue.engagement:
                return HttpResponse('Comment for engagement ignored')
            else:
                raise Http404('No finding or engagement found for this JIRA issue')

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

    # example incoming requests from JIRA Server 8.13.0
    #
    # comment created
    # {
    # "timestamp":1605117321425,
    # "webhookEvent":"comment_created",
    # "comment":{
    #     "self":"http://www.testjira.com/rest/api/2/issue/89820/comment/456843",
    #     "id":"456843",
    #     "author":{
    #         "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
    #         "name":"valentijn",
    #         "key":"valentijn",
    #         "avatarUrls":{
    #             "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
    #             "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
    #             "16x16":"http://www.testjira.com/secure/useravatar?size=x small&ownerId=valentijn&avatarId=11101",
    #             "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
    #         },
    #         "displ ayName":"Valentijn Scholten",
    #         "active":true,
    #         "timeZone":"Europe/Amsterdam"
    #     },
    #     "body":"test2",
    #     "updateAuthor":{
    #         "self":"http://www.testjira.com/rest/ap i/2/user?username=valentijn",
    #         "name":"valentijn",
    #         "key":"valentijn",
    #         "avatarUrls":{
    #             "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
    #             "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
    #             "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
    #             "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valen tijn&avatarId=11101"
    #         },
    #         "displayName":"Valentijn Scholten",
    #         "active":true,
    #         "timeZone":"Europe/Amsterdam"
    #     },
    #     "created":"2020-11-11T18:55:21.425+0100",
    #     "updated":"2020-11-11T18:55:21.425+0100"
    # }
    # }


# issue updated
# {
#    "timestamp":1605117321475,
#    "webhookEvent":"jira:issue_updated",
#    "issue_event_type_name":"issue_commented",
#    "user":{
#       "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#       "name":"valentijn",
#       "key":"valentijn",
#       "emailAddress ":"valentijn.scholten@isaac.nl",
#       "avatarUrls":{
#          "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#          "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#          "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall& ownerId=valentijn&avatarId=11101",
#          "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#       },
#       "displayName ":"Valentijn Scholten",
#       "active":true,
#       "timeZone":"Europe/Amsterdam"
#    },
#    "issue":{
#       "id":"89820",
#       "self":"http://www.testjira.com/rest/api/2/issue/89820 ",
#       "key":"ISEC-277",
#       "fields":{
#          "issuetype":{
#             "self":"http://www.testjira.com/rest/api/2/issuetype/3",
#             "id":"3",
#             "description":"A task is some piece o f work that can be assigned to a user. This does not always result in a quotation/estimate, as it is often some task that needs to be performe d in the context of an existing contract. ",
#             "iconUrl":"http://www.testjira.com/secure/viewavatar?size=xsmall&avatarId=16681&avatarType=issuetype",
#             "name":"Task",
#             "subtask":false,
#             "avatarId":16681
#          },
#          "timespent":null,
#          "customfield_10195":null,
#          "project":{
#             "self":"http://www.testjira.com/rest/api/2/project/13532",
#             "id":"13532",
#             "key":"ISEC",
#             "name":"ISAAC security",
#             "projectTypeKey":"software",
#             "avatarUrls":{
#                "48x48":"http://www.testjira.com/secure/projectavatar?avatarId=14803",
#                "24x24":"http://www.testjira.com/secure/projectavatar?size=small&avatarId=14803",
#                "16x16":"http://www.testjira.com/secure/projectavatar?size=xsmall&avatarId=14803",
#                "32x32":"http://www.testjira.com/secure/projectavatar?size=medium&avatarId=14803"
#             },
#             "projectCategory":{
#                "self":"http://www.testjira.com/rest/api/2/projectCategory/10032",
#                "id":"10032",
#                "description":"All internal isaac projects.",
#                "name":"isaac internal"
#             }
#          },
#          "customfield_10230":null,
#          "fixVersions":[
#          ],
#          "customfield_11440":"0|y02wb8:",
#          "aggregatetimespent":null,
#          "customfield_11640":null,
#          "resolution":null,
#          "customfield_11840":"{summaryBean=com.atlassian.jira.plugin.devstatus.rest.SummaryBean@26e5c00a[summary={pullrequest=com.atlassian.jira.plugin.devstatus.rest.SummaryItemBean@40615a9b[overall=PullRequestOverallBean{stateCount=0, state='OPEN', details=PullRequestOverallDetails{openCount=0, mergedCount=0, declinedCount=0}},byInstanceType={}], build=com.atlassian.jira.plugin.devstatus.rest.SummaryItemBean@7038fe38[overall=com.atlassian.jira.plugin.devstatus.summary.beans.BuildOverallBean@3a47d726[failedBuildCount=0,successfulBuildCount=0,unknownBuildCount=0,count=0,lastUpdated=<null>,lastUpdatedTimestamp=<null>],byInstanceType={}], review=com.atlassian.jira.plugin.devstatus.rest.SummaryItemBean@1bbc2262[overall=com.atlassian.jira.plugin.devstatus.summary.beans.ReviewsOverallBean@4f189579[stateCount=0,state=<null>,dueDate=<null>,overDue=false,count=0,lastUpdated=<null>,lastUpdatedTimestamp=<null>],byInstanceType={}], deployment-environment=com.atlassian.jira.plugin.devstatus.rest.SummaryItemBean@78e67b9c[overall=com.atlassian.jira.plugin.devstatus.summary.beans.DeploymentOverallBean@7c1c7d41[topEnvironments=[],showProjects=false,successfulCount=0,count=0,lastUpdated=<null>,lastUpdatedTimestamp=<null>],byInstanceType={}], repository=com.atlassian.jira.plugin.devstatus.rest.SummaryItemBean@649ff92[overall=com.atlassian.jira.plugin.devstatus.summary.beans.CommitOverallBean@df1117f[count=0,lastUpdated=<null>,lastUpdatedTimestamp=<null>],byInstanceType={}], branch=com.atlassian.jira.plugin.devstatus.rest.SummaryItemBean@4600b1c6[overall=com.atlassian.jira.plugin.devstatus.summary.beans.BranchOverallBean@59e92a32[count=0,lastUpdated=<null>,lastUpdatedTimestamp=<null>],byInstanceType={}]},errors=[],configErrors=[]], devSummaryJson={\"cachedValue\":{\"errors\":[],\"configErrors\":[],\"summary\":{\"pullrequest\":{\"overall\":{\"count\":0,\"lastUpdated\":null,\"stateCount\":0,\"state\":\"OPEN\",\"details\":{\"openCount\":0,\"mergedCount\":0,\"declinedCount\":0,\"total\":0},\"open\":true},\"byInstanceType\":{}},\"build\":{\"overall\":{\"count\":0,\"lastUpdated\":null,\"failedBuildCount\":0,\"successfulBuildCount\":0,\"unknownBuildCount\":0},\"byInstanceType\":{}},\"review\":{\"overall\":{\"count\":0,\"lastUpdated\":null,\"stateCount\":0,\"state\":null,\"dueDate\":null,\"overDue\":false,\"completed\":false},\"byInstanceType\":{}},\"deployment-environment\":{\"overall\":{\"count\":0,\"lastUpdated\":null,\"topEnvironments\":[],\"showProjects\":false,\"successfulCount\":0},\"byInstanceType\":{}},\"repository\":{\"overall\":{\"count\":0,\"lastUpdated\":null},\"byInstanceType\":{}},\"branch\":{\"overall\":{\"count\":0,\"lastUpdated\":null},\"byInstanceType\":{}}}},\"isStale\":false}}",
#          "customfield_10941":null,
#          "resolutiondate":null,
#          "workratio":-1,
#          "lastViewed":"2020-11-11T18:54:32.489+0100",
#          "watches":{
#             "self":"http://www.testjira.com/rest/api/2/issue/ISEC-277/watchers",
#             "watchCount":1,
#             "isWatching":true
#          },
#          "customfield_10060":[
#             "dojo_user(dojo_user)",
#             "valentijn(valentijn)"
#          ],
#          "customfield_10182":null,
#          "created":"2019-04-04T15:38:21.248+0200",
#          "customfield_12043":null,
#          "customfield_10340":null,
#          "customfield_10341":null,
#          "customfield_12045":null,
#          "customfield_10100":null,
#          "priority":{
#             "self":"http://www.testjira.com/rest/api/2/priority/5",
#             "iconUrl":"http://www.testjira.com/images/icons/priorities/trivial.svg",
#             "name":"Trivial (Sev5)",
#             "id":"5"
#          },
#          "customfield_10740":null,
#          "labels":[
#             "NPM_Test",
#             "defect-dojo",
#             "security"
#          ],
#          "timeestimate":null,
#          "aggregatetimeoriginalestimate":null,
#          "issuelinks":[
#          ],
#          "assignee":{
#             "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#             "name":"valentijn",
#             "key":"valentijn",
#             "emailAddress":"valentijn.scholten@isaac.nl",
#             "avatarUrls":{
#                "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#                "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#                "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
#                "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#             },
#             "displayName":"Valentijn Scholten",
#             "active":true,
#             "timeZone":"Europe/Amsterdam"
#          },
#          "updated":"2020-11-11T18:54:32.155+0100",
#          "status":{
#             "self":"http://www.testjira.com/rest/api/2/status/10022",
#             "description":"Incoming/New issues.",
#             "iconUrl":"http://www.testjira.com/isaac_content/icons/isaac_status_new.gif",
#             "name":"New",
#             "id":"10022",
#             "statusCategory":{
#                "self":"http://www.testjira.com/rest/api/2/statuscategory/2",
#                "id":2,
#                "key":"new",
#                "colorName":"blue-gray",
#                "name":"To Do"
#             }
#          },
#          "components":[
#          ],
#          "customfield_10051":"2020-11-11T18:54:32.155+0100",
#          "timeoriginalestimate":null,
#          "customfield_10052":null,
#          "description":"*Regular Expression Denial of Service - (braces, <2.3.1)*\n\n*Severity:* Low\n\n*Product/Engagement:* NPM Test/Jenkins Front-End(develop)*Systems*: \n\n*Description*: \nVersion of `braces` prior to 2.3.1 are vulnerable to Regular Expression Denial of Service (ReDoS). Untrusted input may cause catastrophic backtracking while matching regular expressions. This can cause the application to be unresponsive leading to Denial of Service.\r\n Vulnerable Module: braces\r\n Vulnerable Versions: <2.3.1\r\n Patched Version: >=2.3.1\r\n Vulnerable Path: [u'braces']\r\n CWE: CWE-185\r\n Access: public\n\n*Mitigation*: \nUpgrade to version 2.3.1 or higher.\n\n*Impact*: \nNo impact provided\n\n*References*:https://npmjs.com/advisories/786\n\n*Dojo ID:* 2810\n\n",
#          "customfield_10010":null,
#          "timetracking":{
#          },
#          "attachment":[
#          ],
#          "aggregatetimeestimate":null,
#          "summary":"Regular Expression Denial of Service - (braces, <2.3.1)",
#          "creator":{
#             "self":"http://www.testjira.com/rest/api/2/user?username=dojo_user",
#             "name":"dojo_user",
#             "key":"dojo_user",
#             "emailAddress":"defectdojo@isaac.nl",
#             "avatarUrls":{
#                "48x48":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=48",
#                "24x24":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=24",
#                "16x16":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=16",
#                "32x32":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=32"
#             },
#             "displayName":"Defect Dojo",
#             "active":true,
#             "timeZone":"Europe/Amsterdam"
#          },
#          "customfield_10080":null,
#          "subtasks":[
#          ],
#          "customfield_12140":null,
#          "customfield_10240":"9223372036854775807",
#          "reporter":{
#             "self":"http://www.testjira.com/rest/api/2/user?username=dojo_user",
#             "name":"dojo_user",
#             "key":"dojo_user",
#             "emailAddress":"defectdojo@isaac.nl",
#             "avatarUrls":{
#                "48x48":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=48",
#                "24x24":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=24",
#                "16x16":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=16",
#                "32x32":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=32"
#             },
#             "displayName":"Defect Dojo",
#             "active":true,
#             "timeZone":"Europe/Amsterdam"
#          },
#          "aggregateprogress":{
#             "progress":0,
#             "total":0
#          },
#          "customfield_10640":"9223372036854775807",
#          "customfield_10641":null,
#          "environment":null,
#          "duedate":null,
#          "progress":{
#             "progress":0,
#             "total":0
#          },
#          "comment":{
#             "comments":[
#                {
#                   "self":"http://www.testjira.com/rest/api/2/issue/89820/comment/456841",
#                   "id":"456841",
#                   "author":{
#                      "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#                      "name":"valentijn",
#                      "key":"valentijn",
#                      "emailAddress":"valentijn.scholten@isaac.nl",
#                      "avatarUrls":{
#                         "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#                         "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#                         "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
#                         "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#                      },
#                      "displayName":"Valentijn Scholten",
#                      "active":true,
#                      "timeZone":"Europe/Amsterdam"
#                   },
#                   "body":"test comment valentijn",
#                   "updateAuthor":{
#                      "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#                      "name":"valentijn",
#                      "key":"valentijn",
#                      "emailAddress":"valentijn.scholten@isaac.nl",
#                      "avatarUrls":{
#                         "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#                         "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#                         "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
#                         "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#                      },
#                      "displayName":"Valentijn Scholten",
#                      "active":true,
#                      "timeZone":"Europe/Amsterdam"
#                   },
#                   "created":"2020-11-11T18:54:32.155+0100",
#                   "updated":"2020-11-11T18:54:32.155+0100"
#                },
#                {
#                   "self":"http://www.testjira.com/rest/api/2/issue/89820/comment/456843",
#                   "id":"456843",
#                   "author":{
#                      "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#                      "name":"valentijn",
#                      "key":"valentijn",
#                      "emailAddress":"valentijn.scholten@isaac.nl",
#                      "avatarUrls":{
#                         "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#                         "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#                         "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
#                         "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#                      },
#                      "displayName":"Valentijn Scholten",
#                      "active":true,
#                      "timeZone":"Europe/Amsterdam"
#                   },
#                   "body":"test2",
#                   "updateAuthor":{
#                      "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#                      "name":"valentijn",
#                      "key":"valentijn",
#                      "emailAddress":"valentijn.scholten@isaac.nl",
#                      "avatarUrls":{
#                         "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#                         "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#                         "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
#                         "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#                      },
#                      "displayName":"Valentijn Scholten",
#                      "active":true,
#                      "timeZone":"Europe/Amsterdam"
#                   },
#                   "created":"2020-11-11T18:55:21.425+0100",
#                   "updated":"2020-11-11T18:55:21.425+0100"
#                }
#             ],
#             "maxResults":2,
#             "total":2,
#             "startAt":0
#          },
#          "worklog":{
#             "startAt":0,
#             "maxResults":20,
#             "total":0,
#             "worklogs":[
#             ]
#          }
#       }
#    },
#    "comment":{
#       "self":"http://www.testjira.com/rest/api/2/issue/89820/comment/456843",
#       "id":"456843",
#       "author":{
#          "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#          "name":"valentijn",
#          "key":"valentijn",
#          "emailAddress":"valentijn.scholten@isaac.nl",
#          "avatarUrls":{
#             "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#             "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#             "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
#             "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#          },
#          "displayName":"Valentijn Scholten",
#          "active":true,
#          "timeZone":"Europe/Amsterdam"
#       },
#       "body":"test2",
#       "updateAuthor":{
#          "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#          "name":"valentijn",
#          "key":"valentijn",
#          "emailAddress":"valentijn.scholten@isaac.nl",
#          "avatarUrls":{
#             "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#             "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#             "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
#             "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#          },
#          "displayName":"Valentijn Scholten",
#          "active":true,
#          "timeZone":"Europe/Amsterdam"
#       },
#       "created":"2020-11-11T18:55:21.425+0100",
#       "updated":"2020-11-11T18:55:21.425+0100"
#    }
# }


# issue closed
# {
#    "timestamp":1605125186693,
#    "webhookEvent":"jira:issue_updated",
#    "issue_event_type_name":"issue_closed",
#    "user":{
#       "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#       "name":"valentijn",
#       "key":"valentijn",
#       "emailAddress":"valentijn.scholten@isaac.nl",
#       "avatarUrls":{
#          " 48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#          "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avat arId=11101",
#          "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
#          "32x32":"http://www.testjira.com/secure/useravatar?size=med ium&ownerId=valentijn&avatarId=11101"
#       },
#       "displayName":"Valentijn Scholten",
#       "active":true,
#       "timeZone":"Europe/Amsterdam"
#    },
#    "issue":{
#       "id":"89820",
#       "self":"https://jira.is aac.nl/rest/api/2/issue/89820",
#       "key":"ISEC-277",
#       "fields":{
#          "issuetype":{
#             "self":"http://www.testjira.com/rest/api/2/issuetype/3",
#             "id":"3",
#             "description":"A task is some piece of work that can be assigned to a user. This does not always result in a quotation/estimate, as it is often some task that needs to be performed in the contex t of an existing contract. ",
#             "iconUrl":"http://www.testjira.com/secure/viewavatar?size=xsmall&avatarId=16681&avatarType=issuetype",
#             "name":"Task",
#             "subtask":false,
#             "avatarId":16681
#          },
#          "timespent":null,
#          "customfield_10195":null,
#          "project":{
#             "self":"http://www.testjira.com/rest/api/2/project/13532",
#             "id":"13532",
#             "key":"ISEC",
#             "name":"ISAAC se curity",
#             "projectTypeKey":"software",
#             "avatarUrls":{
#                "48x48":"http://www.testjira.com/secure/projectavatar?avatarId=14803",
#                "24x24":"http://www.testjira.com/secure/projecta vatar?size=small&avatarId=14803",
#                "16x16":"http://www.testjira.com/secure/projectavatar?size=xsmall&avatarId=14803",
#                "32x32":"http://www.testjira.com/secure/projectavatar ?size=medium&avatarId=14803"
#             },
#             "projectCategory":{
#                "self":"http://www.testjira.com/rest/api/2/projectCategory/10032",
#                "id":"10032",
#                "description":"All internal isaac proj ects.",
#                "name":"isaac internal"
#             }
#          },
#          "customfield_10230":null,
#          "fixVersions":[
#          ],
#          "customfield_11440":"0|y02wb8:",
#          "aggregatetimespent":null,
#          "customfield_11640":null,
#          "resol ution":{
#             "self":"http://www.testjira.com/rest/api/2/resolution/11",
#             "id":"11",
#             "description":"Cancelled by the customer.",
#             "name":"Cancelled"
#          },
#          "customfield_11840":"{summa ryBean=com.atlassian.jira.plugin.devstatus.rest.SummaryBean@41db819d[summary={pullrequest=com.atlassian.jira.plugin.devstatus.rest.SummaryItemBean@63de8e7f[overall= PullRequestOverallBean{stateCount=0, state='OPEN', details=PullRequestOverallDetails{openCount=0, mergedCount=0, declinedCount=0}},byInstanceType={}], build=com.atl assian.jira.plugin.devstatus.rest.SummaryItemBean@65f31374[overall=com.atlassian.jira.plugin.devstatus.summary.beans.BuildOverallBean@7249c4c3[failedBuildCount=0,su ccessfulBuildCount=0,unknownBuildCount=0,count=0,lastUpdated=<null>,lastUpdatedTimestamp=<null>],byInstanceType={}], review=com.atlassian.jira.plugin.devstatus.rest .SummaryItemBean@24bf8b85[overall=com.atlassian.jira.plugin.devstatus.summary.beans.ReviewsOverallBean@1127280f[stateCount=0,state=<null>,dueDate=<null>,overDue=fal se,count=0,lastUpdated=<null>,lastUpdatedTimestamp=<null>],byInstanceType={}], deployment-environment=com.atlassian.jira.plugin.devstatus.rest.SummaryItemBean@6cb2f 1ec[overall=com.atlassian.jira.plugin.devstatus.summary.beans.DeploymentOverallBean@50e15f65[topEnvironments=[],showProjects=false,successfulCount=0,count=0,lastUpd ated=<null>,lastUpdatedTimestamp=<null>],byInstanceType={}], repository=com.atlassian.jira.plugin.devstatus.rest.SummaryItemBean@85a055f[overall=com.atlassian.jira. plugin.devstatus.summary.beans.CommitOverallBean@2015230b[count=0,lastUpdated=<null>,lastUpdatedTimestamp=<null>],byInstanceType={}], branch=com.atlassian.jira.plug in.devstatus.rest.SummaryItemBean@5b539b74[overall=com.atlassian.jira.plugin.devstatus.summary.beans.BranchOverallBean@193ed0c[count=0,lastUpdated=<null>,lastUpdate dTimestamp=<null>],byInstanceType={}]},errors=[],configErrors=[]], devSummaryJson={\"cachedValue\":{\"errors\":[],\"configErrors\":[],\"summary\":{\"pullrequest\":{ \"overall\":{\"count\":0,\"lastUpdated\":null,\"stateCount\":0,\"state\":\"OPEN\",\"details\":{\"openCount\":0,\"mergedCount\":0,\"declinedCount\":0,\"total\":0},\" open\":true},\"byInstanceType\":{}},\"build\":{\"overall\":{\"count\":0,\"lastUpdated\":null,\"failedBuildCount\":0,\"successfulBuildCount\":0,\"unknownBuildCount\" :0},\"byInstanceType\":{}},\"review\":{\"overall\":{\"count\":0,\"lastUpdated\":null,\"stateCount\":0,\"state\":null,\"dueDate\":null,\"overDue\":false,\"completed\\ ":false
#       },
#       "\\""byInstanceType\":{}},\"deployment-environment\":{\"overall\":{\"count\":0,\"lastUpdated\":null,\"topEnvironments\":[],\"showProjects\":false,\"successful Count\":0},\"byInstanceType\":{}},\"repository\":{\"overall\":{\"count\":0,\"lastUpdated\":null},\"byInstanceType\":{}},\"branch\":{\"overall\":{\"count\":0,\"lastU pdated\":null},\"byInstanceType\":{}}}},\"isStale\":false}}",
#       "customfield_10941":null,
#       "resolutiondate":"2020-11-11T21:06:26.520+0100",
#       "workratio":-1,
#       "lastViewed":"2 020-11-11T21:06:26.501+0100",
#       "watches":{
#          "self":"http://www.testjira.com/rest/api/2/issue/ISEC-277/watchers",
#          "watchCount":1,
#          "isWatching":true
#       },
#       "customfield_10060":[
#          "de fect.dojo(dojo_user)",
#          "valentijn(valentijn)"
#       ],
#       "customfield_10182":null,
#       "created":"2019-04-04T15:38:21.248+0200",
#       "customfield_12043":null,
#       "customfield_10340":null,
#       "customfield_10341":null,
#       "customfield_12045":null,
#       "customfield_10100":null,
#       "priority":{
#          "self":"http://www.testjira.com/rest/api/2/priority/5",
#          "iconUrl":"https://jira. isaac.nl/images/icons/priorities/trivial.svg",
#          "name":"Trivial (Sev5)",
#          "id":"5"
#       },
#       "customfield_10740":null,
#       "labels":[
#          "NPM_Test",
#          "defect-dojo",
#          "security"
#       ],
#       "timeestimat e":0,
#       "aggregatetimeoriginalestimate":null,
#       "issuelinks":[
#       ],
#       "assignee":{
#          "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#          "name":"valentijn",
#          "key":"va lentijn",
#          "emailAddress":"valentijn.scholten@isaac.nl",
#          "avatarUrls":{
#             "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#             "24x24":"http s://jira.isaac.nl/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#             "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avat arId=11101",
#             "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#          },
#          "displayName":"Valentijn Scholten",
#          "active":true,
#          "timeZo ne":"Europe/Amsterdam"
#       },
#       "updated":"2020-11-11T21:06:26.671+0100",
#       "status":{
#          "self":"http://www.testjira.com/rest/api/2/status/6",
#          "description":"The issue is closed and finished.",
#          "iconUrl":"http://www.testjira.com/isaac_content/icons/isaac_status_closed.gif",
#          "name":"Closed",
#          "id":"6",
#          "statusCategory":{
#             "self":"http://www.testjira.com/r est/api/2/statuscategory/3",
#             "id":3,
#             "key":"done",
#             "colorName":"green",
#             "name":"Done"
#          }
#       },
#       "components":[
#       ],
#       "customfield_10051":"2020-11-11T18:54:32.155+0100",
#       "timeoriginal estimate":null,
#       "customfield_10052":"6_*:*_1_*:*_0_*|*_10022_*:*_1_*:*_50740085426",
#       "description":"*Regular Expression Denial of Service - (braces, <2.3.1)*\n\n*Seve rity:* Low\n\n*Product/Engagement:* NPM Test/Jenkins Front-End(develop)*Systems*: \n\n*Description*: \nVersion of `braces` prior to 2.3.1 are vulnerable to Regular Expression Denial of Service (ReDoS). Untrusted input may cause catastrophic backtracking while matching regular expressions. This can cause the application to be u nresponsive leading to Denial of Service.\r\n Vulnerable Module: braces\r\n Vulnerable Versions: <2.3.1\r\n Patched Version: >=2.3.1\r\n Vulnerable Path: [u'braces']\r\n CWE: CWE-185\r\n Access: public\n\n*Mitigation*: \nUpgrade to version 2.3.1 or higher.\n\n*Impact*: \nNo impact provided\n\n*References*:https://npmjs.com/advisories/786\n\n*Dojo ID:* 2810\n\n",
#       "customfield_10010":null,
#       "timetracking":{
#          "remainingEstimate":"0h",
#          "remainingEstimateSeconds":0
#       },
#       "attachment":[
#       ],
#       "aggregatetimeestimate":0,
#       "summary":"Regular Expression Denial of Service - (braces, <2.3.1)",
#       "creator":{
#          "self":"http://www.testjira.com/rest/api/2/user?username=dojo_user",
#          "name":"dojo_user",
#          "key":"dojo_user",
#          "emailAddress":"defectdojo@isaac.nl",
#          "avatarUrls":{
#             "48x48":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=48",
#             "24x24":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=24",
#             "16x16":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=16",
#             "32x32":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=32"
#          },
#          "displayName":"Defect Dojo",
#          "active":true,
#          "timeZone":"Europe/Amsterdam"
#       },
#       "customfield_10080":null,
#       "subtasks":[
#       ],
#       "customfield_12140":null,
#       "customfield_10240":"9223372036854775807",
#       "reporter":{
#          "self":"http://www.testjira.com/rest/api/2/user?username=dojo_user",
#          "name":"dojo_user",
#          "key":"dojo_user",
#          "emailAddress":"defectdojo@isaac.nl",
#          "avatarUrls":{
#             "48x48":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=48",
#             "24x24":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=24",
#             "16x16":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=16",
#             "32x32":"https://www.gravatar.com/avatar/9637bfb970eff6176357df615f548f1c?d=mm&s=32"
#          },
#          "displayName":"Defect Dojo",
#          "active":true,
#          "timeZone":"Europe/Amsterdam"
#       },
#       "aggregateprogress":{
#          "progress":0,
#          "total":0
#       },
#       "customfield_10640":"9223372036854775807",
#       "customfield_10641":null,
#       "environment":null,
#       "duedate":null,
#       "progress":{
#          "progress":0,
#          "total":0
#       },
#       "comment":{
#          "comments":[
#             {
#                "self":"http://www.testjira.com/rest/api/2/issue/89820/comment/456841",
#                "id":"456841",
#                "author":{
#                   "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#                   "name":"valentijn",
#                   "key":"valentijn",
#                   "emailAddress":"valentijn.scholten@isaac.nl",
#                   "avatarUrls":{
#                      "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#                      "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#                      "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
#                      "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#                   },
#                   "displayName":"Valentijn Scholten",
#                   "active":true,
#                   "timeZone":"Europe/Amsterdam"
#                },
#                "body":"test comment valentijn",
#                "updateAuthor":{
#                   "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#                   "name":"valentijn",
#                   "key":"valentijn",
#                   "emailAddress":"valentijn.scholten@isaac.nl",
#                   "avatarUrls":{
#                      "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#                      "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#                      "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
#                      "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#                   },
#                   "displayName":"Valentijn Scholten",
#                   "active":true,
#                   "timeZone":"Europe/Amsterdam"
#                },
#                "created":"2020-11-11T18:54:32.155+0100",
#                "updated":"2020-11-11T18:54:32.155+0100"
#             },
#             {
#                "self":"http://www.testjira.com/rest/api/2/issue/89820/comment/456843",
#                "id":"456843",
#                "author":{
#                   "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#                   "name":"valentijn",
#                   "key":"valentijn",
#                   "emailAddress":"valentijn.scholten@isaac.nl",
#                   "avatarUrls":{
#                      "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#                      "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#                      "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
#                      "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#                   },
#                   "displayName":"Valentijn Scholten",
#                   "active":true,
#                   "timeZone":"Europe/Amsterdam"
#                },
#                "body":"test2",
#                "updateAuthor":{
#                   "self":"http://www.testjira.com/rest/api/2/user?username=valentijn",
#                   "name":"valentijn",
#                   "key":"valentijn",
#                   "emailAddress":"valentijn.scholten@isaac.nl",
#                   "avatarUrls":{
#                      "48x48":"http://www.testjira.com/secure/useravatar?ownerId=valentijn&avatarId=11101",
#                      "24x24":"http://www.testjira.com/secure/useravatar?size=small&ownerId=valentijn&avatarId=11101",
#                      "16x16":"http://www.testjira.com/secure/useravatar?size=xsmall&ownerId=valentijn&avatarId=11101",
#                      "32x32":"http://www.testjira.com/secure/useravatar?size=medium&ownerId=valentijn&avatarId=11101"
#                   },
#                   "displayName":"Valentijn Scholten",
#                   "active":true,
#                   "timeZone":"Europe/Amsterdam"
#                },
#                "created":"2020-11-11T18:55:21.425+0100",
#                "updated":"2020-11-11T18:55:21.425+0100"
#             }
#          ],
#          "maxResults":2,
#          "total":2,
#          "startAt":0
#       },
#       "worklog":{
#          "startAt":0,
#          "maxResults":20,
#          "total":0,
#          "worklogs":[
#          ]
#       }
#    }
# },
# "changelog":{
#    "id":"1212064",
#    "items":[
#       {
#          "field":"resolution",
#          "fieldtype":"jira",
#          "from":null,
#          "fromString":null,
#          "to":"11",
#          "toString":"Cancelled"
#       },
#       {
#          "field":"status",
#          "fieldtype":"jira",
#          "from":"10022",
#          "fromString":"New",
#          "to":"6",
#          "toString":"Closed"
#       },
#       {
#          "field":"timeestimate",
#          "fieldtype":"jira",
#          "from":null,
#          "fromString":null,
#          "to":"0",
#          "toString":"0"
#       }
#    ]
# }
# }
