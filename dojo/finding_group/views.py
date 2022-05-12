# #  findings
from dojo.utils import Product_Tab
from dojo.forms import DeleteFindingGroupForm
from dojo.notifications.helper import create_notification
from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.db.utils import DEFAULT_DB_ALIAS
from django.http.response import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls.base import reverse
from django.views.decorators.http import require_POST
from dojo.models import Finding_Group
import logging
import dojo.jira_link.helper as jira_helper
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions

logger = logging.getLogger(__name__)


@user_is_authorized(Finding_Group, Permissions.Finding_Group_View, 'fgid')
def view_finding_group(request, fgid):
    logger.debug('view finding group: %s', fgid)
    return HttpResponse('Not implemented yet')


@user_is_authorized(Finding_Group, Permissions.Finding_Group_Edit, 'fgid')
def edit_finding_group(request, fgid):
    logger.debug('edit finding group: %s', fgid)
    return HttpResponse('Not implemented yet')


@user_is_authorized(Finding_Group, Permissions.Finding_Group_Delete, 'fgid')
@require_POST
def delete_finding_group(request, fgid):
    logger.debug('delete finding group: %s', fgid)
    finding_group = get_object_or_404(Finding_Group, pk=fgid)
    form = DeleteFindingGroupForm(instance=finding_group)

    if request.method == 'POST':
        if 'id' in request.POST and str(finding_group.id) == request.POST['id']:
            form = DeleteFindingGroupForm(request.POST, instance=finding_group)
            if form.is_valid():
                product = finding_group.test.engagement.product
                finding_group.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Finding Group and relationships removed.',
                                     extra_tags='alert-success')

                create_notification(event='other',
                                    title='Deletion of %s' % finding_group.name,
                                    product=product,
                                    description='The finding group "%s" was deleted by %s' % (finding_group.name, request.user),
                                    url=request.build_absolute_uri(reverse('view_test', args=(finding_group.test.id,))),
                                    icon="exclamation-triangle")
                return HttpResponseRedirect(reverse('view_test', args=(finding_group.test.id,)))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([finding_group])
    rels = collector.nested()
    product_tab = Product_Tab(finding_group.test.engagement.product, title="Product", tab="settings")

    return render(request, 'dojo/delete_finding_group.html',
                  {'finding_group': finding_group,
                   'form': form,
                   'product_tab': product_tab,
                   'rels': rels,
                   })


@user_is_authorized(Finding_Group, Permissions.Finding_Group_Edit, 'fgid')
@require_POST
def unlink_jira(request, fgid):
    logger.debug('/finding_group/%s/jira/unlink', fgid)
    group = get_object_or_404(Finding_Group, id=fgid)
    logger.info('trying to unlink a linked jira issue from %d:%s', group.id, group.name)
    if group.has_jira_issue:
        try:
            jira_helper.unlink_jira(request, group)

            messages.add_message(
                request,
                messages.SUCCESS,
                'Link to JIRA issue succesfully deleted',
                extra_tags='alert-success')

            return JsonResponse({'result': 'OK'})
        except Exception as e:
            logger.exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                'Link to JIRA could not be deleted, see alerts for details',
                extra_tags='alert-danger')

            return HttpResponse(status=500)
    else:
        messages.add_message(
            request,
            messages.ERROR,
            'Link to JIRA not found',
            extra_tags='alert-danger')
        return HttpResponse(status=400)


@user_is_authorized(Finding_Group, Permissions.Finding_Group_Edit, 'fgid')
@require_POST
def push_to_jira(request, fgid):
    logger.debug('/finding_group/%s/jira/push', fgid)
    group = get_object_or_404(Finding_Group, id=fgid)
    try:
        logger.info('trying to push %d:%s to JIRA to create or update JIRA issue', group.id, group.name)
        logger.debug('pushing to jira from group.push_to-jira()')

        # it may look like succes here, but the push_to_jira are swallowing exceptions
        # but cant't change too much now without having a test suite, so leave as is for now with the addition warning message to check alerts for background errors.
        if jira_helper.push_to_jira(group, sync=True):
            messages.add_message(
                request,
                messages.SUCCESS,
                message='Action queued to create or update linked JIRA issue, check alerts for background errors.',
                extra_tags='alert-success')
        else:
            messages.add_message(
                request,
                messages.SUCCESS,
                'Push to JIRA failed, check alerts on the top right for errors',
                extra_tags='alert-danger')

        return JsonResponse({'result': 'OK'})
    except Exception as e:
        logger.exception(e)
        logger.error('Error pushing to JIRA: ', exc_info=True)
        messages.add_message(
            request,
            messages.ERROR,
            'Error pushing to JIRA',
            extra_tags='alert-danger')
        return HttpResponse(status=500)
    # return redirect_to_return_url_or_else(request, reverse('view_finding', args=(group.id,)))
