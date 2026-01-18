import logging
from contextlib import suppress
from pathlib import Path

from auditlog.models import LogEntry
from django.apps import apps
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse

from dojo.authorization.authorization import (
    user_has_configuration_permission_or_403,
    user_has_permission,
    user_has_permission_or_403,
)
from dojo.authorization.roles_permissions import Permissions
from dojo.filters import LogEntryFilter, PgHistoryFilter
from dojo.forms import ManageFileFormSet
from dojo.models import (
    App_Analysis,
    Dojo_User,
    Endpoint,
    Engagement,
    FileUpload,
    Finding,
    Finding_Template,
    Objects_Product,
    Product,
    Test,
)
from dojo.pghistory_models import DojoEvents
from dojo.product_announcements import ErrorPageProductAnnouncement
from dojo.utils import Product_Tab, generate_file_response, get_page_items

logger = logging.getLogger(__name__)


def get_object_str(event):
    """Get the __str__ representation of the original object from pghistory event data."""
    try:
        if not hasattr(event, "pgh_obj_model") or not event.pgh_obj_model:
            return "N/A"

        app_label, model_name = event.pgh_obj_model.split(".")

        # Handle through model events specially - look up related objects
        pgh_data = getattr(event, "pgh_data", None) or {}

        if model_name == "FindingTags" and pgh_data:
            return _get_tag_event_str(Finding, "tags", pgh_data, "tagulous_finding_tags_id")
        if model_name == "FindingInheritedTags" and pgh_data:
            return _get_tag_event_str(Finding, "inherited_tags", pgh_data, "tagulous_finding_inherited_tags_id")
        if model_name == "ProductTags" and pgh_data:
            return _get_tag_event_str(Product, "tags", pgh_data, "tagulous_product_tags_id")
        if model_name == "EngagementTags" and pgh_data:
            return _get_tag_event_str(Engagement, "tags", pgh_data, "tagulous_engagement_tags_id")
        if model_name == "EngagementInheritedTags" and pgh_data:
            return _get_tag_event_str(Engagement, "inherited_tags", pgh_data, "tagulous_engagement_inherited_tags_id")
        if model_name == "TestTags" and pgh_data:
            return _get_tag_event_str(Test, "tags", pgh_data, "tagulous_test_tags_id")
        if model_name == "TestInheritedTags" and pgh_data:
            return _get_tag_event_str(Test, "inherited_tags", pgh_data, "tagulous_test_inherited_tags_id")
        if model_name == "EndpointTags" and pgh_data:
            return _get_tag_event_str(Endpoint, "tags", pgh_data, "tagulous_endpoint_tags_id")
        if model_name == "EndpointInheritedTags" and pgh_data:
            return _get_tag_event_str(Endpoint, "inherited_tags", pgh_data, "tagulous_endpoint_inherited_tags_id")
        if model_name == "FindingTemplateTags" and pgh_data:
            return _get_finding_template_tag_str(pgh_data)
        if model_name == "AppAnalysisTags" and pgh_data:
            return _get_app_analysis_tag_str(pgh_data)
        if model_name == "ObjectsProductTags" and pgh_data:
            return _get_objects_product_tag_str(pgh_data)
        if model_name == "FindingReviewers" and pgh_data:
            return _get_reviewer_event_str(pgh_data)

        # Regular models - try to load from database first for accurate __str__
        model_class = apps.get_model(app_label, model_name)
        obj_id = getattr(event, "pgh_obj_id", None)
        if obj_id:
            try:
                instance = model_class.objects.get(pk=obj_id)
                return str(instance)
            except model_class.DoesNotExist:
                pass

        # Fallback: try to extract useful info from pgh_data
        if pgh_data:
            # Try common field names that would give a meaningful string
            for field in ["title", "name", "username", "cve"]:
                if pgh_data.get(field):
                    return str(pgh_data[field])

        if obj_id:
            return f"{model_name} #{obj_id}"
        return "N/A"  # noqa: TRY300 it complains that it wants an else, but if I add an else, it complains that the else is unnecessary

    except (ValueError, LookupError, TypeError, AttributeError):
        # Fallback to name from data if available
        pgh_data = getattr(event, "pgh_data", None) or {}
        for field in ["title", "name", "username", "cve"]:
            if pgh_data.get(field):
                return str(pgh_data[field])

        if hasattr(event, "pgh_obj_id") and event.pgh_obj_id:
            return f"Object #{event.pgh_obj_id}"

        return "N/A"


def _get_tag_event_str(parent_model, field_name, pgh_data, tag_fk_name):
    """Get a descriptive string for tag through model events."""
    tag_id = pgh_data.get(tag_fk_name)
    if not tag_id:
        return f"Tag on {parent_model.__name__}"

    # Get the tag model via the parent model's field
    tag_model = parent_model._meta.get_field(field_name).remote_field.model
    try:
        tag = tag_model.objects.get(pk=tag_id)
    except tag_model.DoesNotExist:
        # Tag was deleted - show ID
        return f"Tag (deleted, ID {tag_id}) on {parent_model.__name__}"
    else:
        return f"Tag '{tag.name}' on {parent_model.__name__}"


def _get_finding_template_tag_str(pgh_data):
    """Get a descriptive string for Finding Template tag events."""
    tag_id = pgh_data.get("tagulous_finding_template_tags_id")
    if not tag_id:
        return "Tag on Finding Template"
    tag_model = Finding_Template._meta.get_field("tags").remote_field.model
    try:
        tag = tag_model.objects.get(pk=tag_id)
    except tag_model.DoesNotExist:
        return f"Tag (deleted, ID {tag_id}) on Finding Template"
    else:
        return f"Tag '{tag.name}' on Finding Template"


def _get_app_analysis_tag_str(pgh_data):
    """Get a descriptive string for App Analysis tag events."""
    tag_id = pgh_data.get("tagulous_app_analysis_tags_id")
    if not tag_id:
        return "Tag on App Analysis"
    tag_model = App_Analysis._meta.get_field("tags").remote_field.model
    try:
        tag = tag_model.objects.get(pk=tag_id)
    except tag_model.DoesNotExist:
        return f"Tag (deleted, ID {tag_id}) on App Analysis"
    else:
        return f"Tag '{tag.name}' on App Analysis"


def _get_objects_product_tag_str(pgh_data):
    """Get a descriptive string for Objects Product tag events."""
    tag_id = pgh_data.get("tagulous_objects_product_tags_id")
    if not tag_id:
        return "Tag on Objects Product"
    tag_model = Objects_Product._meta.get_field("tags").remote_field.model
    try:
        tag = tag_model.objects.get(pk=tag_id)
    except tag_model.DoesNotExist:
        return f"Tag (deleted, ID {tag_id}) on Objects Product"
    else:
        return f"Tag '{tag.name}' on Objects Product"


def _get_reviewer_event_str(pgh_data):
    """Get a descriptive string for reviewer through model events."""
    user_id = pgh_data.get("dojo_user_id")
    finding_id = pgh_data.get("finding_id")

    if user_id:
        try:
            user = Dojo_User.objects.get(id=user_id)
            user_str = user.get_full_name() or user.username
        except Dojo_User.DoesNotExist:
            user_str = f"User ID {user_id}"
        return f"Reviewer '{user_str}' on Finding #{finding_id}"

    return f"Reviewer on Finding #{finding_id}"


def get_object_url(event):
    """Get the URL to the object from pghistory event data."""
    try:
        if not hasattr(event, "pgh_obj_model") or not event.pgh_obj_model:
            return None

        app_label, model_name = event.pgh_obj_model.split(".")
        pgh_data = getattr(event, "pgh_data", None) or {}
        obj_id = getattr(event, "pgh_obj_id", None)

        # For through models, link to the parent object instead
        if model_name in {"FindingTags", "FindingInheritedTags", "FindingReviewers"}:
            finding_id = pgh_data.get("finding_id")
            if finding_id:
                return f"/finding/{finding_id}"
            return None
        if model_name == "ProductTags":
            product_id = pgh_data.get("product_id")
            if product_id:
                return f"/product/{product_id}"
            return None
        if model_name in {"EngagementTags", "EngagementInheritedTags"}:
            engagement_id = pgh_data.get("engagement_id")
            if engagement_id:
                return f"/engagement/{engagement_id}"
            return None
        if model_name in {"TestTags", "TestInheritedTags"}:
            test_id = pgh_data.get("test_id")
            if test_id:
                return f"/test/{test_id}"
            return None
        if model_name in {"EndpointTags", "EndpointInheritedTags"}:
            endpoint_id = pgh_data.get("endpoint_id")
            if endpoint_id:
                return f"/endpoint/{endpoint_id}"
            return None
        if model_name == "FindingTemplateTags":
            finding_template_id = pgh_data.get("finding_template_id")
            if finding_template_id:
                return f"/template/{finding_template_id}/edit"
            return None
        if model_name in {"AppAnalysisTags", "ObjectsProductTags"}:
            # These don't have direct view pages
            return None

        # For regular models, try to get the URL via get_absolute_url
        if not obj_id:
            return None

        model_class = apps.get_model(app_label, model_name)
        try:
            instance = model_class.objects.get(pk=obj_id)
        except model_class.DoesNotExist:
            return None
        else:
            if hasattr(instance, "get_absolute_url"):
                return instance.get_absolute_url()
            return None

    except (ValueError, LookupError, TypeError, AttributeError):
        return None


def custom_error_view(request, exception=None):
    ErrorPageProductAnnouncement(request=request)
    return render(request, "500.html", {}, status=500)


def custom_unauthorized_view(request, exception=None):
    ErrorPageProductAnnouncement(request=request)
    return render(request, "403.html", {}, status=400)


def custom_bad_request_view(request, exception=None):
    ErrorPageProductAnnouncement(request=request)
    return render(request, "400.html", {}, status=400)


def action_history(request, cid, oid):
    try:
        ct = ContentType.objects.get_for_id(cid)
        obj = ct.get_object_for_this_type(pk=oid)
    except (KeyError, ObjectDoesNotExist):
        raise Http404

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
        user_has_configuration_permission_or_403(request.user, "auth.view_user")
    elif not request.user.is_superuser:
        raise PermissionDenied

    product_tab = None
    if product_id:
        product_tab = Product_Tab(get_object_or_404(Product, id=product_id), title="History", tab=active_tab)
        if active_tab == "engagements":
            if str(ct) == "engagement":
                product_tab.setEngagement(object_value)
            else:
                product_tab.setEngagement(object_value.engagement)

    # Get audit history from pghistory (and legacy django-auditlog entries if available)
    auditlog_history = []
    pghistory_history = []

    # Try to get django-auditlog entries
    auditlog_queryset = LogEntry.objects.filter(
        content_type=ct,
        object_pk=obj.id,
    ).order_by("-timestamp")
    auditlog_history = auditlog_queryset

    # Use custom DojoEvents proxy model - provides proper diff calculation and context fields
    # Filter by the specific object using references() method
    # references() returns events where any FK points to the object (including through models like tags/reviewers)
    # Note: Events is a CTE that doesn't support select_related, but includes context data
    pghistory_history = DojoEvents.objects.references(obj).order_by("-pgh_created_at")

    # Add object string representation based on the original models __str__ method
    # this value was available in the old auditlogs, so we mimic that here
    # it can be useful to see the object_str that was changed, but we'll have to see how it performs

    # Apply filtering first, then process for object strings
    pghistory_filter = PgHistoryFilter(request.GET, queryset=pghistory_history)
    filtered_pghistory = pghistory_filter.qs

    # Process filtered events to add object string representation and URL
    processed_events = []
    for event in filtered_pghistory:
        event.object_str = get_object_str(event)
        event.object_url = get_object_url(event)
        processed_events.append(event)

    # Paginate the processed events
    paged_pghistory_history = get_page_items(request, processed_events, 25)

    # Create filter and pagination for auditlog entries
    auditlog_filter = LogEntryFilter(request.GET, queryset=auditlog_history)
    paged_auditlog_history = get_page_items(request, auditlog_filter.qs, 25)

    if not settings.ENABLE_AUDITLOG:
        messages.add_message(
            request,
            messages.WARNING,
            "Audit logging is currently disabled in System Settings.",
            extra_tags="alert-danger")

    return render(request, "dojo/action_history.html",
                  {"auditlog_history": paged_auditlog_history,
                   "pghistory_history": paged_pghistory_history,
                   "product_tab": product_tab,
                   "filtered": auditlog_history,
                   "log_entry_filter": auditlog_filter,
                   "pghistory_filter": pghistory_filter,
                   "obj": obj,
                   "test": test,
                   "object_value": object_value,
                   "finding": finding,
                   })


def manage_files(request, oid, obj_type):
    if obj_type == "Engagement":
        obj = get_object_or_404(Engagement, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Engagement_Edit)
        obj_vars = ("view_engagement", "engagement_set")
    elif obj_type == "Test":
        obj = get_object_or_404(Test, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Test_Edit)
        obj_vars = ("view_test", "test_set")
    elif obj_type == "Finding":
        obj = get_object_or_404(Finding, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Finding_Edit)
        obj_vars = ("view_finding", "finding_set")
    else:
        raise Http404

    files_formset = ManageFileFormSet(queryset=obj.files.all())
    error = False

    if request.method == "POST":
        files_formset = ManageFileFormSet(
            request.POST, request.FILES, queryset=obj.files.all())
        if files_formset.is_valid():
            # remove all from database and disk

            files_formset.save()

            for o in files_formset.deleted_objects:
                logger.debug("removing file: %s", o.file.name)
                with suppress(FileNotFoundError):
                    (Path(settings.MEDIA_ROOT) / o.file.name).unlink()

            for o in files_formset.new_objects:
                logger.debug("adding file: %s", o.file.name)
                obj.files.add(o)

            orphan_files = FileUpload.objects.filter(engagement__isnull=True,
                                                     test__isnull=True,
                                                     finding__isnull=True)
            for o in orphan_files:
                logger.debug("purging orphan file: %s", o.file.name)
                with suppress(FileNotFoundError):
                    (Path(settings.MEDIA_ROOT) / o.file.name).unlink()
                o.delete()

            messages.add_message(
                request,
                messages.SUCCESS,
                "Files updated successfully.",
                extra_tags="alert-success")

        else:
            error = True
            messages.add_message(
                request,
                messages.ERROR,
                "Please check form data and try again.",
                extra_tags="alert-danger")

        if not error:
            return HttpResponseRedirect(reverse(obj_vars[0], args=(oid, )))
    return render(
        request, "dojo/manage_files.html", {
            "files_formset": files_formset,
            "obj": obj,
            "obj_type": obj_type,
        })


@login_required
def protected_serve(request, path, document_root=None, *, show_indexes=False):
    """Serve the file only after verifying the user is supposed to see the file."""
    file = get_object_or_404(FileUpload, file=path)
    object_set = list(file.engagement_set.all()) + list(file.test_set.all()) + list(file.finding_set.all())
    # Determine if there is an object to query permission checks from
    if len(object_set) == 0:
        raise Http404
    # Should only one item (but not sure what type) in the list, so O(n=1)
    for obj in object_set:
        if isinstance(obj, Engagement):
            user_has_permission_or_403(request.user, obj, Permissions.Engagement_View)
        elif isinstance(obj, Test):
            user_has_permission_or_403(request.user, obj, Permissions.Test_View)
        elif isinstance(obj, Finding):
            user_has_permission_or_403(request.user, obj, Permissions.Finding_View)

    return generate_file_response(file)


def access_file(request, fid, oid, obj_type, *, url=False):
    def check_file_belongs_to_object(file, object_manager, object_id):
        if not object_manager.filter(id=object_id).exists():
            raise PermissionDenied

    file = get_object_or_404(FileUpload, pk=fid)
    if obj_type == "Engagement":
        obj = get_object_or_404(Engagement, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Engagement_View)
        obj_manager = file.engagement_set
    elif obj_type == "Test":
        obj = get_object_or_404(Test, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Test_View)
        obj_manager = file.test_set
    elif obj_type == "Finding":
        obj = get_object_or_404(Finding, pk=oid)
        user_has_permission_or_403(request.user, obj, Permissions.Finding_View)
        obj_manager = file.finding_set
    else:
        raise Http404
    check_file_belongs_to_object(file, obj_manager, obj.id)

    return generate_file_response(file)
