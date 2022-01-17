import logging
import os
from auditlog.models import LogEntry
from django.contrib.contenttypes.models import ContentType
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist
from django.http import Http404, HttpResponseRedirect
from django.conf import settings
from django.urls import reverse
from django.shortcuts import render, get_object_or_404
from dojo.models import Engagement, Test, Finding, Endpoint, Product, FileUpload
from dojo.filters import LogEntryFilter
from dojo.forms import ManageFileFormSet
from dojo.utils import get_page_items, Product_Tab, get_system_setting
from dojo.authorization.authorization import user_has_permission, user_has_permission_or_403, user_has_configuration_permission_or_403
from dojo.authorization.roles_permissions import Permissions


logger = logging.getLogger(__name__)


def action_history(request, cid, oid):
    try:
        ct = ContentType.objects.get_for_id(cid)
        obj = ct.get_object_for_this_type(pk=oid)
    except (KeyError, ObjectDoesNotExist):
        raise Http404()

    product_id = None
    active_tab = None
    finding = None
    test = False
    object_value = None

    if ct.model == "product":
        user_has_permission_or_403(request.user, obj, Permissions.Product_View)
        product_id = obj.id
        active_tab = "overview"
        object_value = Product.objects.get(id=obj.id)
    elif ct.model == "engagement":
        user_has_permission_or_403(request.user, obj, Permissions.Engagement_View)
        object_value = Engagement.objects.get(id=obj.id)
        product_id = object_value.product.id
        active_tab = "engagements"
    elif ct.model == "test":
        user_has_permission_or_403(request.user, obj, Permissions.Test_View)
        object_value = Test.objects.get(id=obj.id)
        product_id = object_value.engagement.product.id
        active_tab = "engagements"
        test = True
    elif ct.model == "finding":
        user_has_permission_or_403(request.user, obj, Permissions.Finding_View)
        object_value = Finding.objects.get(id=obj.id)
        product_id = object_value.test.engagement.product.id
        active_tab = "findings"
        finding = object_value
    elif ct.model == "endpoint":
        user_has_permission_or_403(request.user, obj, Permissions.Endpoint_View)
        object_value = Endpoint.objects.get(id=obj.id)
        product_id = object_value.product.id
        active_tab = "endpoints"
    elif ct.model == "risk_acceptance":
        engagements = Engagement.objects.filter(risk_acceptance=obj)
        authorized = False
        for engagement in engagements:
            if user_has_permission(request.user, engagement, Permissions.Engagement_View):
                authorized = True
                break
        if not authorized:
            raise PermissionDenied
    elif ct.model == "user":
        user_has_configuration_permission_or_403(request.user, 'auth.view_user', legacy='superuser')
    else:
        if not request.user.is_superuser:
            raise PermissionDenied

    product_tab = None
    if product_id:
        product_tab = Product_Tab(product_id, title="History", tab=active_tab)
        if active_tab == "engagements":
            if str(ct) == "engagement":
                product_tab.setEngagement(object_value)
            else:
                product_tab.setEngagement(object_value.engagement)

    history = LogEntry.objects.filter(content_type=ct,
                                      object_pk=obj.id).order_by('-timestamp')
    history = LogEntryFilter(request.GET, queryset=history)
    paged_history = get_page_items(request, history.qs, 25)

    if not get_system_setting('enable_auditlog'):
        messages.add_message(
            request,
            messages.WARNING,
            'Audit logging is currently disabled in System Settings.',
            extra_tags='alert-danger')

    return render(request, 'dojo/action_history.html',
                  {"history": paged_history,
                   'product_tab': product_tab,
                   "filtered": history,
                   "obj": obj,
                   "test": test,
                   "object_value": object_value,
                   "finding": finding
                   })


def manage_files(request, oid, obj_type):
    if obj_type == 'Engagement':
        obj = get_object_or_404(Engagement, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Engagement_Edit)
        obj_vars = ('view_engagement', 'engagement_set')
    elif obj_type == 'Test':
        obj = get_object_or_404(Test, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Test_Edit)
        obj_vars = ('view_test', 'test_set')
    elif obj_type == 'Finding':
        obj = get_object_or_404(Finding, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Finding_Edit)
        obj_vars = ('view_finding', 'finding_set')
    else:
        raise Http404()

    files_formset = ManageFileFormSet(queryset=obj.files.all())
    error = False

    if request.method == 'POST':
        files_formset = ManageFileFormSet(
            request.POST, request.FILES, queryset=obj.files.all())
        if files_formset.is_valid():
            # remove all from database and disk

            files_formset.save()

            for o in files_formset.deleted_objects:
                logger.debug("removing file: %s", o.file.name)
                os.remove(os.path.join(settings.MEDIA_ROOT, o.file.name))

            for o in files_formset.new_objects:
                logger.debug("adding file: %s", o.file.name)
                obj.files.add(o)

            orphan_files = FileUpload.objects.filter(engagement__isnull=True,
                                                     test__isnull=True,
                                                     finding__isnull=True)
            for o in orphan_files:
                logger.debug("purging orphan file: %s", o.file.name)
                os.remove(os.path.join(settings.MEDIA_ROOT, o.file.name))
                o.delete()

            messages.add_message(
                request,
                messages.SUCCESS,
                'Files updated successfully.',
                extra_tags='alert-success')

        else:
            error = True
            messages.add_message(
                request,
                messages.ERROR,
                'Please check form data and try again.',
                extra_tags='alert-danger')

        if not error:
            return HttpResponseRedirect(reverse(obj_vars[0], args=(oid, )))
    return render(
        request, 'dojo/manage_files.html', {
            'files_formset': files_formset,
            'obj': obj,
            'obj_type': obj_type,
        })
