import logging
from dojo.utils import get_system_setting
import os
import io
import requests
from django.conf import settings
from django.template.loader import render_to_string
from django.utils import timezone
from jira import JIRA
from jira.exceptions import JIRAError
from dojo.models import Finding, Test, Engagement, Product, JIRA_Issue,\
    System_Settings, Notes, JIRA_Instance
from requests.auth import HTTPBasicAuth
from dojo.notifications.helper import create_notification
from django.contrib import messages
from celery.decorators import task
from dojo.decorators import dojo_async_task
from dojo.utils import get_current_request, truncate_with_dots
from django.urls import reverse


logger = logging.getLogger(__name__)


def is_jira_enabled():
    if not get_system_setting('enable_jira'):
        logger.debug('JIRA is disabled, not doing anything')
        return False

    return True


def is_jira_configured_and_enabled(obj):
    if not is_jira_enabled():
        return False

    if get_jira_project(obj) is None:
        logger.debug('JIRA project not found for: "%s" not doing anything', obj)
        return False

    return True


def is_push_to_jira(instance, push_to_jira_parameter=None):
    if not is_jira_configured_and_enabled(instance):
        return False

    jira_project = get_jira_project(instance)

    # caller explicitly stated true or false (False is different from None!)
    if push_to_jira_parameter is not None:
        return push_to_jira_parameter

    # push_to_jira was not specified, so look at push_all_issues in JIRA_Project
    return jira_project.push_all_issues


def is_push_all_issues(instance):
    if not is_jira_configured_and_enabled(instance):
        return False

    jira_project = get_jira_project(instance)
    if jira_project:
        return jira_project.push_all_issues


def get_jira_project(obj):
    if not is_jira_enabled():
        return None

    if obj is None:
        return None

    if isinstance(obj, Finding):
        finding = obj
        return get_jira_project(finding.test)

    if isinstance(obj, Test):
        test = obj
        return get_jira_project(test.engagement)

    if isinstance(obj, Engagement):
        # TODO refactor relationships, but now this would brake APIv1 (and v2?)
        engagement = obj
        jira_project = engagement.product.jira_project_set.all()[0]  # first() doesn't work with prefetching
        logger.debug('found jira_instance %s for %s', jira_project, engagement)
        return jira_project

    if isinstance(obj, Product):
        # TODO refactor relationships, but now this would brake APIv1 (and v2?)
        product = obj
        jira_project = product.jira_project_set.all()[0]  # first() doesn't work with prefetching
        logger.debug('found jira_instance %s for %s', jira_project, product)
        return jira_project


def get_jira_instance(instance):
    if not is_jira_enabled():
        return False

    jira_project = get_jira_project(instance)
    if jira_project:
        logger.debug('found jira_instance %s for %s', jira_project.jira_instance, instance)
        return jira_project.jira_instance

    return None


def get_jira_url(obj):
    jira_project = get_jira_project(obj)

    if not jira_project:
        return None

    jira_url = ''
    if isinstance(obj, Finding) or isinstance(obj, Engagement):
        if obj.has_jira_issue:
            jira_url = jira_project.jira_instance.url + '/browse/' + obj.jira_issue.jira_key
        else:
            # if there is no issue, we show the url to the jira project (which is attached to product)
            return get_jira_url(finding.test.engagement.product)
    elif isinstance(obj, Product):
        jira_url = jira_project.jira_instance.url + '/browse/' + jira_project.project_key

    # TODO: JIRA: Add url for engagement/product/instance
    return jira_url


def get_jira_key(obj):
    jira_project = get_jira_project(obj)

    if not get_jira_project:
        return None

    jira_key = ''
    if isinstance(obj, Finding) or isinstance(obj, Engagement):
        if obj.has_jira_issue:
            jira_key = obj.jira_issue.jira_key

    return jira_key


def get_jira_creation(obj):
    if isinstance(obj, Finding) or isinstance(obj, Engagement):
        if obj.has_jira_issue:
            return obj.jira_issue.jira_creation
    return None


def get_jira_change(obj):
    if isinstance(obj, Finding) or isinstance(obj, Engagement):
        if obj.has_jira_issue:
            return obj.jira_issue.jira_change
    return None


def has_jira_issue(obj):
    if isinstance(obj, Finding) or isinstance(obj, Engagement):
        try:
            return obj.jira_issue is not None
        except JIRA_Issue.DoesNotExist:
            return False

    return False


def has_jira_configured(obj):
    return get_jira_project(obj) is not None


# Gets a connection to a Jira server based on the finding
def get_jira_connection(obj):
    jira = None

    jira_instance = obj
    if not isinstance(jira_instance, JIRA_Instance):
        jira_instance = get_jira_instance(obj)

    if jira_instance is not None:
        try:
            jira = JIRA(
                server=jira_instance.url,
                basic_auth=(jira_instance.username, jira_instance.password),
                options={"verify": settings.JIRA_SSL_VERIFY},
                max_retries=0)

            logger.debug('logged in to JIRA %s successfully', jira_instance)

            return jira
        except Exception as e:
            logger.exception(e)
            messages.add_message(get_current_request(),
                                messages.ERROR,
                                'Unable to authenticate. Please check the URL, username, password, IP whitelist, Network connection.',
                                extra_tags='alert-danger')
            raise e


def jira_get_resolution_id(jira, issue, status):
    transitions = jira.transitions(issue)
    resolution_id = None
    for t in transitions:
        if t['name'] == "Resolve Issue":
            resolution_id = t['id']
            break
        if t['name'] == "Reopen Issue":
            resolution_id = t['id']
            break

    return resolution_id


def jira_change_resolution_id(jira, issue, id):
    jira.transition_issue(issue, id)


# Logs the error to the alerts table, which appears in the notification toolbar
def log_jira_generic_alert(title, description):
    create_notification(
        event='jira_update',
        title=title,
        description=description,
        icon='bullseye',
        source='JIRA')


# Logs the error to the alerts table, which appears in the notification toolbar
def log_jira_alert(error, finding):
    prod_name = finding.test.engagement.product.name if finding else 'unknown'

    create_notification(
        event='jira_update',
        title='JIRA update issue' + '(' + truncate_with_dots(prod_name, 25) + ')',
        description='Finding: ' + str(finding.id if finding else 'unknown') + ', ' + error,
        url=reverse('view_finding', args=(finding.id, )) if finding else None,
        icon='bullseye',
        source='JIRA update',
        finding=finding)


# Displays an alert for Jira notifications
def log_jira_message(text, finding):
    create_notification(
        event='jira_update',
        title='Jira update message',
        description=text + " Finding: " + str(finding.id),
        url=reverse('view_finding', args=(finding.id, )),
        icon='bullseye',
        source='JIRA', finding=finding)


def get_labels(find):
    # Update Label with system setttings label
    labels = []
    system_settings = System_Settings.objects.get()
    system_labels = system_settings.jira_labels
    if system_labels is None:
        return
    else:
        system_labels = system_labels.split()
    if len(system_labels) > 0:
        for system_label in system_labels:
            labels.append(system_label)
    # Update the label with the product name (underscore)
    prod_name = find.test.engagement.product.name.replace(" ", "_")
    labels.append(prod_name)
    return labels


def jira_description(find):
    template = 'issue-trackers/jira-description.tpl'
    kwargs = {}
    kwargs['finding'] = find
    kwargs['jira_instance'] = find.jira_instance_new()
    return render_to_string(template, kwargs)


def push_to_jira(obj):
    if isinstance(obj, Finding):
        finding = obj
        if finding.has_jira_issue:
            update_jira_issue(finding)
        else:
            add_jira_issue(finding)

    elif isinstance(obj, Engagement):
        engagement = obj
        if engagement.has_jira_issue:
            update_epic(engagement)
        else:
            add_epic(engagement)

    else:
        logger.error('unsupported object passed to push_to_jira: %s %i %s', obj.__name__, obj.id, obj)


@dojo_async_task
@task
def add_jira_issue(find):
    logger.info('trying to create a new jira issue for %d:%s', find.id, find.title)

    if not is_jira_enabled():
        return

    if not is_jira_configured_and_enabled(find):
        logger.error("Finding {} cannot be pushed to JIRA as there is no JIRA configuration for this product.".format(find.id))
        log_jira_alert('Finding cannot be pushed to JIRA as there is no JIRA configuration for this product.', find)
        return

    jira_minimum_threshold = Finding.get_number_severity(System_Settings.objects.get().jira_minimum_severity)

    jira_project = get_jira_project(find)
    jira_instance = get_jira_instance(find)

    if 'Active' in find.status() and 'Verified' in find.status():
        if jira_minimum_threshold > Finding.get_number_severity(find.severity):
            log_jira_alert('Finding below the minimum JIRA severity threshold.', find)
            logger.warn("Finding {} is below the minimum JIRA severity threshold.".format(find.id))
            logger.warn("The JIRA issue will NOT be created.")
            return

        logger.debug('Trying to create a new JIRA issue for finding {}...'.format(find.id))
        try:
            JIRAError.log_to_tempfile = False
            jira = get_jira_connection(jira_instance)
            meta = None

            fields = {
                    'project': {
                        'key': jira_project.project_key
                    },
                    'summary': find.title,
                    'description': jira_description(find),
                    'issuetype': {
                        'name': jira_instance.default_issue_type
                    },
            }

            if jira_project.component:
                fields['components'] = [
                        {
                            'name': jira_project.component
                        },
                ]

            # populate duedate field, but only if it's available for this project + issuetype
            if not meta:
                meta = jira_meta(jira, jira_project)

            if 'priority' in meta['projects'][0]['issuetypes'][0]['fields']:
                fields['priority'] = {
                                        'name': jira_instance.get_priority(find.severity)
                                    }

            labels = get_labels(find)
            if labels:
                if 'labels' in meta['projects'][0]['issuetypes'][0]['fields']:
                    fields['labels'] = labels

            if System_Settings.objects.get().enable_finding_sla:

                if 'duedate' in meta['projects'][0]['issuetypes'][0]['fields']:
                    # jira wants YYYY-MM-DD
                    duedate = find.sla_deadline().strftime('%Y-%m-%d')
                    fields['duedate'] = duedate

            if len(find.endpoints.all()) > 0:
                if not meta:
                    meta = jira_meta(jira, jira_project)

                if 'environment' in meta['projects'][0]['issuetypes'][0]['fields']:
                    environment = "\n".join([str(endpoint) for endpoint in find.endpoints.all()])
                    fields['environment'] = environment

            logger.debug('sending fields to JIRA: %s', fields)

            new_issue = jira.create_issue(fields)

            j_issue = JIRA_Issue(
                jira_id=new_issue.id, jira_key=new_issue.key, finding=find)
            j_issue.jira_creation = timezone.now()
            j_issue.jira_change = timezone.now()
            j_issue.save()
            issue = jira.issue(new_issue.id)

            find.save(push_to_jira=False, dedupe_option=False, issue_updater_option=False)

            jira_issue_url = get_jira_issue_url(find)

            new_note = Notes()
            new_note.entry = 'created JIRA issue %s for finding' % (jira_issue_url)
            new_note.author, created = User.objects.get_or_create(username='JIRA')  # quick hack copied from webhook because we don't have request.user here
            new_note.save()
            find.notes.add(new_note)

            # Upload dojo finding screenshots to Jira
            for pic in find.images.all():
                jira_attachment(
                    find, jira, issue,
                    settings.MEDIA_ROOT + pic.image_large.name)

                # if jira_project.enable_engagement_epic_mapping:
                #      epic = eng.jira_issue
                #      issue_list = [j_issue.jira_id,]
                #      jira.add_jira_issues_to_epic(epic_id=epic.jira_id, issue_keys=[str(j_issue.jira_id)], ignore_epics=True)
        except JIRAError as e:
            logger.exception(e)
            log_jira_alert(e.text, find)
    else:
        log_jira_alert("A Finding needs to be both Active and Verified to be pushed to JIRA.", find)
        logger.warning("A Finding needs to be both Active and Verified to be pushed to JIRA: %s", find)


@dojo_async_task
@task
def update_jira_issue(find):
    logger.info('trying to update a linked jira issue for %d:%s', find.id, find.title)

    if not is_jira_enabled():
        return False

    jira_project = get_jira_project(find)
    jira_instance = get_jira_instance(find)

    if not jira_project:
        logger.error("Finding {} cannot be pushed to JIRA as there is no JIRA configuration for this product.".format(find.id))
        log_jira_alert('Finding cannot be pushed to JIRA as there is no JIRA configuration for this product.', find)
        return

    j_issue = find.jira_issue
    try:
        JIRAError.log_to_tempfile = False
        jira = get_jira_connection(jira_instance)

        issue = jira.issue(j_issue.jira_id)

        meta = None

        fields = {}
        # Only update the component if it didn't exist earlier in Jira, this is to avoid assigning multiple components to an item
        if issue.fields.components:
            log_jira_alert(
                "Component not updated, exists in Jira already. Update from Jira instead.",
                find)
        elif jira_project.component:
            # Add component to the Jira issue
            component = [
                {
                    'name': jira_project.component
                },
            ]
            fields = {"components": component}

        if not meta:
            meta = jira_meta(jira, jira_project)

        labels = get_labels(find)
        if labels:
            if 'labels' in meta['projects'][0]['issuetypes'][0]['fields']:
                fields['labels'] = labels

        if len(find.endpoints.all()) > 0:
            if 'environment' in meta['projects'][0]['issuetypes'][0]['fields']:
                environment = "\n".join([str(endpoint) for endpoint in find.endpoints.all()])
                fields['environment'] = environment

        # Upload dojo finding screenshots to Jira
        for pic in find.images.all():
            jira_attachment(find, jira, issue,
                            settings.MEDIA_ROOT + pic.image_large.name)

        logger.debug('sending fields to JIRA: %s', fields)

        issue.update(
            summary=find.title,
            description=jira_description(find),
            priority={'name': jira_instance.get_priority(find.severity)},
            fields=fields)

        find.jira_issue.jira_change = timezone.now()
        find.jira_issue.save()
        find.save(push_to_jira=False, dedupe_option=False, issue_updater_option=False)

    except JIRAError as e:
        logger.exception(e)
        log_jira_alert(e.text, find)

    req_url = jira_instance.url + '/rest/api/latest/issue/' + \
        j_issue.jira_id + '/transitions'
    if 'Inactive' in find.status() or 'Mitigated' in find.status(
    ) or 'False Positive' in find.status(
    ) or 'Out of Scope' in find.status() or 'Duplicate' in find.status():
        # if 'Active' in old_status:
        json_data = {'transition': {'id': jira_instance.close_status_key}}
        r = requests.post(
            url=req_url,
            auth=HTTPBasicAuth(jira_instance.username, jira_instance.password),
            json=json_data)
        if r.status_code != 204:
            logger.warn("JIRA transition failed with error: {}".format(r.text))
        find.jira_issue.jira_change = timezone.now()
        find.jira_issue.save()
        find.save()
    elif 'Active' in find.status() and 'Verified' in find.status():
        # if 'Inactive' in old_status:
        json_data = {'transition': {'id': jira_instance.open_status_key}}
        r = requests.post(
            url=req_url,
            auth=HTTPBasicAuth(jira_instance.username, jira_instance.password),
            json=json_data)
        if r.status_code != 204:
            logger.warn("JIRA transition failed with error: {}".format(r.text))
        find.jira_issue.jira_change = timezone.now()
        find.jira_issue.save()
        find.save()


def jira_meta(jira, jpkey):
    meta = jira.createmeta(projectKeys=jpkey.project_key, issuetypeNames=jpkey.conf.default_issue_type, expand="projects.issuetypes.fields")
    logger.debug("jira_meta: %s", json.dumps(meta, indent=4))  # this is None safe
    return meta


def jira_attachment(finding, jira, issue, file, jira_filename=None):
    basename = file
    if jira_filename is None:
        basename = os.path.basename(file)

    # Check to see if the file has been uploaded to Jira
    # TODO: JIRA: check for local existince of attachment as it currently crashes if local attachment doesn't exist
    if jira_check_attachment(issue, basename) is False:
        try:
            if jira_filename is not None:
                attachment = io.StringIO()
                attachment.write(jira_filename)
                jira.add_attachment(
                    issue=issue, attachment=attachment, filename=jira_filename)
            else:
                # read and upload a file
                with open(file, 'rb') as f:
                    jira.add_attachment(issue=issue, attachment=f)
        except JIRAError as e:
            logger.exception(e)
            log_jira_alert("Attachment: " + e.text, finding)


def jira_check_attachment(issue, source_file_name):
    file_exists = False
    for attachment in issue.fields.attachment:
        filename = attachment.filename

        if filename == source_file_name:
            file_exists = True
            break

    return file_exists


@dojo_async_task
@task
def close_epic(eng, push_to_jira):
    engagement = eng
    if not is_jira_enabled():
        return False

    if not is_jira_configured_and_enabled(engagement):
        return False

    jira_project = get_jira_project(engagement)
    jira_instance = get_jira_instance(engagement)
    if jira_project.enable_engagement_epic_mapping and push_to_jira:
        try:
            j_issue = eng.jira_issue
            req_url = jira_instance.url + '/rest/api/latest/issue/' + \
                j_issue.jira_id + '/transitions'
            json_data = {'transition': {'id': jira_instance.close_status_key}}
            r = requests.post(
                url=req_url,
                auth=HTTPBasicAuth(jira_instance.username, jira_instance.password),
                json=json_data)
            if r.status_code != 204:
                logger.warn("JIRA close epic failed with error: {}".format(r.text))
        except Exception as e:
            log_jira_generic_alert('Jira Engagement/Epic Close Error', str(e))
            pass


@dojo_async_task
@task
def update_epic(eng):
    engagement = eng

    if not is_jira_configured_and_enabled(engagement):
        return False

    jira_project = get_jira_project(engagement)
    jira_instance = get_jira_instance(engagement)
    if jira_project.enable_engagement_epic_mapping:
        try:
            jira = get_jira_connection(jira_instance)
            j_issue = eng.jira_issue
            issue = jira.issue(j_issue.jira_id)
            issue.update(summary=eng.name, description=eng.name)
        except Exception as e:
            log_jira_generic_alert('Jira Engagement/Epic Update Error', str(e))
            pass


@dojo_async_task
@task
def add_epic(eng):
    logger.info('trying to create a new jira EPIC for %d:%s', eng.id, eng.name)
    engagement = eng

    if not is_jira_configured_and_enabled(engagement):
        return False

    jira_project = get_jira_project(engagement)
    jira_instance = get_jira_instance(engagement)
    if jira_project.enable_engagement_epic_mapping:
        issue_dict = {
            'project': {
                'key': jira_project.project_key
            },
            'summary': engagement.name,
            'description': engagement.name,
            'issuetype': {
                'name': 'Epic'
            },
            'customfield_' + str(jira_instance.epic_name_id): engagement.name,
        }
        try:
            jira = get_jira_connection(jira_instance)
            new_issue = jira.create_issue(fields=issue_dict)
            j_issue = JIRA_Issue(
                jira_id=new_issue.id,
                jira_key=new_issue.key,
                engagement=engagement)
            j_issue.save()
        except Exception as e:
            error = str(e)
            message = ""
            if "customfield" in error:
                message = "The 'Epic name id' in your DefectDojo Jira Configuration does not appear to be correct. Please visit, " + jira_instance.url + \
                    "/rest/api/2/field and search for Epic Name. Copy the number out of cf[number] and place in your DefectDojo settings for Jira and try again. For example, if your results are cf[100001] then copy 100001 and place it in 'Epic name id'. (Your Epic Id will be different.) \n\n"

            log_jira_generic_alert('Jira Engagement/Epic Creation Error',
                                   message + error)
            pass


def jira_get_issue(jira_project, issue_key):
    jira_instance = jira_project.jira_instance
    try:
        jira = get_jira_connection(jira_instance)
        issue = jira.issue(issue_key)

        return issue
    except JIRAError as jira_error:
        logger.debug('error retrieving jira issue ' + issue_key + ' ' + str(jira_error))
        logger.exception(jira_error)
        log_jira_generic_alert('error retrieving jira issue ' + issue_key, str(jira_error))
        return None


@dojo_async_task
@task
def add_comment(find, note, force_push=False):
    if not is_jira_configured_and_enabled(find):
        return False

    logger.debug('trying to add a comment to a linked jira issue for: %d:%s', find.id, find.title)
    if not note.private:
        jira_project = get_jira_project(find)
        jira_instance = get_jira_instance(find)

        if jira_project.push_notes or force_push is True:
            try:
                jira = get_jira_connection(jira_instance)
                j_issue = find.jira_issue
                jira.add_comment(
                    j_issue.jira_id,
                    '(%s): %s' % (note.author.get_full_name(), note.entry))
            except Exception as e:
                log_jira_generic_alert('Jira Add Comment Error', str(e))
                pass


def add_simple_jira_comment(jira_instance, jira_issue, comment):
    try:
        jira = get_jira_connection(jira_instance)

        jira.add_comment(
            jira_issue.jira_id, comment
        )
    except Exception as e:
        log_jira_generic_alert('Jira Add Comment Error', str(e))


def finding_link_jira(request, finding, new_jira_issue_key):
    logger.debug('linking existing jira issue %s for finding %i', new_jira_issue_key, finding.id)

    existing_jira_issue = jira_helper.jira_get_issue(jira_helper.get_jira_project(finding), new_jira_issue_key)

    if not existing_jira_issue:
        raise ValueError('JIRA issue not found or cannot be retrieved: ' + new_jira_issue_key)

    jira_issue = JIRA_Issue(
        jira_id=existing_jira_issue.id,
        jira_key=existing_jira_issue.key,
        finding=finding)

    jira_issue.jira_key = new_jira_issue_key
    # jira timestampe are in iso format: 'updated': '2020-07-17T09:49:51.447+0200'
    # seems to be a pain to parse these in python < 3.7, so for now just record the curent time as
    # as the timestamp the jira link was created / updated in DD
    jira_issue.jira_creation = timezone.now()
    jira_issue.jira_change = timezone.now()

    jira_issue.save()

    finding.save(push_to_jira=False, dedupe_option=False, issue_updater_option=False)

    jira_issue_url = jira_helper.get_jira_url(finding)

    new_note = Notes()
    new_note.entry = 'linked JIRA issue %s to finding' % (jira_issue_url)
    new_note.author = request.user
    new_note.save()
    finding.notes.add(new_note)


def finding_unlink_jira(request, finding):
    logger.debug('removing linked jira issue %s for finding %i', finding.jira_issue.jira_key, finding.id)
    finding.jira_issue.delete()
    finding.save(push_to_jira=False, dedupe_option=False, issue_updater_option=False)

    jira_issue_url = jira_helper.get_jira_url(finding)

    new_note = Notes()
    new_note.entry = 'unlinked JIRA issue %s from finding' % (jira_issue_url)
    new_note.author = request.user
    new_note.save()
    finding.notes.add(new_note)
