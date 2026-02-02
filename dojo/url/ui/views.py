import logging
from datetime import datetime

from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import call_command
from django.db import DEFAULT_DB_ALIAS
from django.http import HttpRequest, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone

from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.endpoint.utils import endpoint_meta_import
from dojo.forms import (
    DeleteEndpointForm,
    DojoMetaFormSet,
    ImportEndpointMetaForm,
)
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.queries import annotate_location_counts_and_status, get_authorized_locations
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import DojoMeta, Finding, Product
from dojo.reports.views import generate_report
from dojo.url.filters import URLFilter
from dojo.url.models import URL
from dojo.url.queries import annotate_host_contents
from dojo.url.ui.forms import URLForm
from dojo.utils import (
    Product_Tab,
    add_breadcrumb,
    add_error_message_to_response,
    get_page_items,
    get_period_counts,
    get_setting,
    is_scan_file_too_large,
    redirect,
)

logger = logging.getLogger(__name__)


@user_is_authorized(Location, Permissions.Location_View, "location_id")
def view_endpoint(request: HttpRequest, location_id: int):
    return process_endpoint_view(request, location_id, host_view=False)


@user_is_authorized(Location, Permissions.Location_View, "location_id")
def view_endpoint_host(request: HttpRequest, location_id: int):
    return process_endpoint_view(request, location_id, host_view=True)


def all_endpoints(request):
    return process_endpoints_view(request, host_view=False, vulnerable=False)


def all_endpoint_hosts(request):
    return process_endpoints_view(request, host_view=True, vulnerable=False)


def vulnerable_endpoints(request):
    return process_endpoints_view(request, host_view=False, vulnerable=True)


def vulnerable_endpoint_hosts(request):
    return process_endpoints_view(request, host_view=True, vulnerable=True)


def process_endpoint_view(request: HttpRequest, location_id: int, *, host_view=False):
    """
    Renders the endpoint or host view for a given location, displaying findings and related metadata.

    Args:
        request (HttpRequest): The HTTP request object.
        location_id (int): The ID of the Location to display.
        host_view (bool, optional): If True, displays the host view aggregating all endpoints for the host.
            If False, displays the view for a single endpoint. Defaults to False.

    Returns:
        HttpResponse: Rendered HTML response for the endpoint or host view.

    Context:
        - location: The Location object being viewed.
        - locations: List of Location objects (only in host view).
        - host: Hostname of the location.
        - product_tab: Product_Tab object if a product is selected.
        - findings: Paginated active findings for the location or host.
        - all_findings: All findings related to the location or host.
        - active_findings_count: Count of active findings.
        - all_findings_count: Count of all findings.
        - opened_per_month: Monthly counts of opened findings.
        - metadata: Metadata dictionary for the location (only in endpoint view).
        - status: Status string for the location in the context of the selected product.
        - host_view: Boolean indicating if host view is enabled.

    """
    location = get_object_or_404(Location, id=location_id)
    host = location.url.host
    locations = None
    metadata = None
    status = "No relationships defined"
    base_findings = Finding.objects.only(
        "id",
        "title",
        "severity",
        "epss_score",
        "epss_percentile",
        "date",
        "found_by",
        "active",
        "out_of_scope",
        "mitigated",
        "false_p",
        "duplicate",
        "found_by",
    ).prefetch_related("locations__location", "found_by")

    if host_view:
        # In host view, aggregate all locations (endpoints) sharing the same host.
        locations = annotate_host_contents(
            get_authorized_locations(
                permission=Permissions.Location_View,
                queryset=Location.objects.prefetch_related("tags", "url").filter(
                    location_type=URL.LOCATION_TYPE, url__host=host,
                ),
                user=request.user,
            ),
        )
        # Gather all findings related to any of the locations for this host.
        all_findings = base_findings.filter(
            locations__location__id__in=locations.values_list("id", flat=True),
        ).distinct()
    else:
        # In endpoint view, show findings and metadata for the specific location.
        all_findings = base_findings.filter(locations__location=location).distinct()
        # Gather metadata for the location as a dictionary of name/value pairs.
        metadata = dict(location.location_meta.values_list("name", "value"))

    # Filter active findings for the location or host, ordered by severity
    active_findings = all_findings.filter(locations__status=FindingLocationStatus.Active).order_by("numerical_severity")
    # Calculate the number of months between the first and last finding for this endpoint or host
    if all_findings:
        # Use the date of the oldest finding as the start date
        start_date = timezone.make_aware(datetime.combine(all_findings.last().date, datetime.min.time()))
    else:
        # If there are no findings, use the current time as the start date
        start_date = timezone.now()
    end_date = timezone.now()

    # Calculate the number of months between the start and end dates
    relative_time = relativedelta(end_date, start_date)
    months_between = (relative_time.years * 12) + relative_time.months
    # Include the current month in the count
    months_between += 1
    # closed_findings is required for get_period_counts, but not relevant for endpoint view
    closed_findings = Finding.objects.none()
    # Get monthly counts of opened findings for the endpoint or host
    monthly_counts = get_period_counts(
        all_findings,
        closed_findings,
        None,
        months_between,
        start_date,
        relative_delta="months",
    )
    paged_findings = get_page_items(request, active_findings, 25)
    # Add the product tab if we are filtering by a single product
    product_tab = None
    if "product" in request.GET:
        product = request.GET.getlist("product", [])
        if len(product) == 1:
            # If a single product is selected, get the product and check permissions
            product = get_object_or_404(Product, id=product[0])
            user_has_permission_or_403(request.user, product, Permissions.Product_View)
            # Create the product tab for the view
            product_tab = Product_Tab(product, "Host" if host_view else "Endpoint", tab="endpoints")
            # Get the status of the location for the selected product
            status = location.status_from_product(product)

    return render(
        request,
        "dojo/url/view.html",
        {
            "location": location,
            "locations": locations,
            "host": host,
            "product_tab": product_tab,
            "findings": paged_findings,
            "all_findings": all_findings,
            "active_findings_count": active_findings.count(),
            "all_findings_count": all_findings.count(),
            "opened_per_month": monthly_counts["opened_per_period"],
            "metadata": metadata,
            "status": status,
            "host_view": host_view,
        },
    )


def process_endpoints_view(request, *, host_view=False, vulnerable=False):
    """
    Renders the endpoints or hosts list view, optionally filtered by vulnerability status.

    Args:
        request (HttpRequest): The HTTP request object.
        host_view (bool, optional): If True, displays the host view aggregating endpoints by host.
        vulnerable (bool, optional): If True, filters to only active/vulnerable endpoints or hosts.

    Returns:
        HttpResponse: Rendered HTML response for the endpoints or hosts list view.

    Context:
        - product_tab: Product_Tab object if a single product is selected.
        - locations: Paginated Location queryset (endpoints or hosts).
        - filtered: URLFilter object for further filtering in the template.
        - location_count: Total count of endpoints or hosts after filtering.
        - mitigated_location_count: Count of endpoints or hosts with mitigated status.
        - name: Name of the view ("All Endpoints", "Vulnerable Hosts", etc.).
        - host_view: Boolean indicating if host view is enabled.

    """
    # Determine the view name and get authorized endpoints
    view_name = "Vulnerable" if vulnerable else "All"
    locations = get_authorized_locations(
        permission=Permissions.Location_View,
        queryset=Location.objects.prefetch_related("tags", "url").filter(location_type=URL.LOCATION_TYPE),
        user=request.user,
    )
    # Filter by active/vulnerable if requested
    if vulnerable:
        locations = locations.filter(products__status=ProductLocationStatus.Active)
    # Now apply the host/endpoint view specific filtering
    if host_view:
        # Host view: aggregate locations by host and annotate with findings/products counts and status
        view_name += " Hosts"
        locations = URLFilter(
            request.GET,
            queryset=annotate_host_contents(locations.order_by("url__host").distinct("url__host")),
            user=request.user,
        )
        location_count = locations.qs.count()
        mitigated_location_count = locations.qs.filter(overall_status=ProductLocationStatus.Mitigated).count()
    else:
        # Endpoint view: show all endpoints with overall status annotation
        view_name += " Endpoints"
        locations = URLFilter(request.GET, queryset=annotate_location_counts_and_status(locations), user=request.user)
        # Count total and mitigated endpoints after filtering
        location_count = locations.qs.count()
        mitigated_location_count = locations.qs.filter(overall_status=ProductLocationStatus.Mitigated).count()
    # Do the pagination
    paged_locations = get_page_items(request, locations.qs, 25)
    # Add the breadcrumb
    add_breadcrumb(title=view_name, top_level=not len(request.GET), request=request)
    # Add the product tab if we are filtering by a single product
    product_tab = None
    if "product" in request.GET:
        products = request.GET.getlist("product", [])
        if len(products) == 1:
            # If a single product is selected, get the product and check permissions
            product = get_object_or_404(Product, id=products[0])
            user_has_permission_or_403(request.user, product, Permissions.Product_View)
            # Create the product tab for the view
            product_tab = Product_Tab(product, view_name, tab="endpoints")

    return render(
        request,
        "dojo/url/list.html",
        {
            "product_tab": product_tab,
            "locations": paged_locations,
            "filtered": locations,
            "location_count": location_count,
            "mitigated_location_count": mitigated_location_count,
            "name": view_name,
            "host_view": host_view,
        },
    )


@user_is_authorized(Location, Permissions.Location_Edit, "location_id")
def edit_endpoint(request, location_id):
    # Retrieve the Location object by ID and add breadcrumb for editing
    location = get_object_or_404(Location, id=location_id)
    add_breadcrumb(parent=location, title="Edit", top_level=False, request=request)
    # Initialize the URLForm with the current URL instance for editing
    form = URLForm(instance=location.url)
    if request.method == "POST":
        # Handle form submission for editing an endpoint
        form = URLForm(request.POST, instance=location.url)
        if form.is_valid():
            try:
                form.save(update_only=True)
            except ValidationError:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "That URL already exists.",
                    extra_tags="alert-danger",
                )
            else:
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    "Endpoint updated successfully.",
                    extra_tags="alert-success",
                )
            # Redirect to the endpoint view after successful update
            return HttpResponseRedirect(reverse("view_endpoint", args=(location.id,)))

    return render(
        request,
        "dojo/url/update.html",
        {"form": form},
    )


@user_is_authorized(Product, Permissions.Location_Add, "product_id")
def add_endpoint_to_product(request, product_id):
    # Retrieve the Product object by ID and initialize the URLForm for adding a new endpoint
    product = get_object_or_404(Product, id=product_id)
    form = URLForm()
    # Handle form submission for adding a new endpoint to a product
    if request.method == "POST":
        form = URLForm(request.POST)
        if form.is_valid():
            # Save the new URL instance
            url = form.save()
            # Associate the new endpoint with the selected product
            url.location.associate_with_product(product)
            # Display a success message to the user
            messages.add_message(request, messages.SUCCESS, "Endpoint added successfully.", extra_tags="alert-success")
            # Redirect to the endpoint list view for the product
            return HttpResponseRedirect(reverse("endpoint") + f"?product={product_id}")

    product_tab = Product_Tab(product, "Add Endpoint", tab="endpoints")
    return render(request, "dojo/url/create.html", {"product_tab": product_tab, "form": form})


@user_is_authorized(Product, Permissions.Location_Add, "finding_id")
def add_endpoint_to_finding(request, finding_id):
    # Retrieve the Finding object by ID and get its associated Product
    finding = get_object_or_404(Finding, id=finding_id)
    product = finding.test.engagement.product
    form = URLForm()
    # Handle form submission for adding a new endpoint to a finding
    if request.method == "POST":
        form = URLForm(request.POST)
        if form.is_valid():
            # First save the URL instance
            url = form.save()
            # Associate the new endpoint with the selected finding
            url.location.associate_with_finding(finding)
            # Display a success message to the user
            messages.add_message(request, messages.SUCCESS, "Endpoint added successfully.", extra_tags="alert-success")
            # Redirect to the endpoint list view for the product
            return HttpResponseRedirect(reverse("endpoint") + f"?product={product.id}")
    product_tab = Product_Tab(product, "Add Endpoint", tab="endpoints")
    return render(request, "dojo/url/create.html", {"product_tab": product_tab, "form": form})


@user_is_authorized(Location, Permissions.Location_Delete, "location_id")
def delete_endpoint(request, location_id):
    # Retrieve the Location object by primary key and initialize the delete form
    location = get_object_or_404(Location, pk=location_id)
    form = DeleteEndpointForm(instance=location)
    # Handle POST request for deleting an endpoint and its relationships
    if request.method == "POST":
        form = DeleteEndpointForm(request.POST, instance=location)
        if form.is_valid():
            # Delete the location, which will also cascade delete related findings and product references
            location.delete()
            messages.add_message(
                request, messages.SUCCESS, "Endpoint and relationships removed.", extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("endpoint"))
    # Preview the relationships that will be deleted along with the endpoint.
    # If DELETE_PREVIEW setting is enabled, use Django's NestedObjects to collect related objects.
    rels = ["Previewing the relationships has been disabled.", ""]
    if get_setting("DELETE_PREVIEW"):
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([location])
        rels = collector.nested()

    return render(
        request,
        "dojo/url/delete.html",
        {
            "location": location,
            "form": form,
            "rels": rels,
        },
    )


@user_is_authorized(Location, Permissions.Location_Edit, "location_id")
def manage_meta_data(request, location_id):
    # Retrieve the Location object by ID and filter its associated metadata
    location = Location.objects.get(id=location_id)
    meta_data_query = DojoMeta.objects.filter(location=location)
    # Map the foreign key for the formset to the location
    form_mapping = {"location": location}
    # Initialize the DojoMetaFormSet with the metadata queryset and mapping
    formset = DojoMetaFormSet(queryset=meta_data_query, form_kwargs={"fk_map": form_mapping})
    if request.method == "POST":
        formset = DojoMetaFormSet(request.POST, queryset=meta_data_query, form_kwargs={"fk_map": form_mapping})
        if formset.is_valid():
            formset.save()
            messages.add_message(
                request, messages.SUCCESS, "Metadata updated successfully.", extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_endpoint", args=(location_id,)))
    add_breadcrumb(parent=location, title="Manage Metadata", top_level=False, request=request)
    return render(
        request,
        "dojo/edit_metadata.html",
        {"formset": formset},
    )


@user_is_authorized(Product, Permissions.Location_Edit, "product_id")
def import_endpoint_meta(request, product_id):
    # Retrieve the Product object by ID and initialize the import form
    product = get_object_or_404(Product, id=product_id)
    form = ImportEndpointMetaForm()
    if request.method == "POST":
        # Handle POST request for importing endpoint metadata
        form = ImportEndpointMetaForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES.get("file", None)
            # Check if the uploaded file exceeds the maximum allowed size
            if file and is_scan_file_too_large(file):
                messages.add_message(
                    request,
                    messages.ERROR,
                    f"Report file is too large. Maximum supported size is {settings.SCAN_FILE_MAX_SIZE} MB",
                    extra_tags="alert-danger",
                )
            # Get import options from the cleaned form data
            create_endpoints = form.cleaned_data["create_endpoints"]
            create_tags = form.cleaned_data["create_tags"]
            create_dojo_meta = form.cleaned_data["create_dojo_meta"]
            # Attempt to import endpoint metadata using the uploaded file and selected options.
            try:
                endpoint_meta_import(
                    file,
                    product,
                    create_endpoints,
                    create_tags,
                    create_dojo_meta,
                    origin="UI",
                    request=request,
                    object_class=Location,
                )
            except Exception as e:
                # Log the exception and display an error message to the user.
                logger.exception("An exception error occurred during the report import")
                add_error_message_to_response(f"An exception error occurred during the report import:{e}")
            # Redirect to the endpoint list view for the product after import.
            return HttpResponseRedirect(reverse("endpoint") + f"?product={product_id}")
    # Add breadcrumb and product tab for the endpoint meta importer view
    add_breadcrumb(title="Endpoint Meta Importer", top_level=False, request=request)
    product_tab = Product_Tab(product, title="Endpoint Meta Importer", tab="endpoints")
    return render(
        request,
        "dojo/endpoint_meta_importer.html",
        {
            "product_tab": product_tab,
            "form": form,
        },
    )


# bulk mitigate and delete are combined, so we can't have the nice user_is_authorized decorator
def endpoint_bulk_update_all(request, product_id=None):
    if request.method == "POST":
        # Get the list of endpoint IDs to update from the POST request
        locations_to_update = request.POST.getlist("endpoints_to_update")
        # Query the Location objects matching the selected IDs
        locations = Location.objects.filter(id__in=locations_to_update)
        # Store the total count for later use in authorization and messaging
        total_location_count = locations.count()

        if request.POST.get("delete_bulk_endpoints") and locations_to_update:
            # If a product_id is provided, check user authorization for deletion on that product
            if product_id is not None:
                product = get_object_or_404(Product, id=product_id)
                user_has_permission_or_403(request.user, product, Permissions.Location_Delete)
            # Filter locations to only those the user is authorized to delete
            locations = get_authorized_locations(Permissions.Location_Delete, locations, request.user)
            skipped_location_count = total_location_count - locations.count()
            deleted_location_count = locations.count()
            # This will also delete related finding and product location references via cascade
            locations.delete()
            # Notify user if any locations were skipped due to lack of authorization
            if skipped_location_count > 0:
                add_error_message_to_response(
                    f"Skipped deletion of {skipped_location_count} locations because you are not authorized.",
                )
            # Add a success message if any locations were deleted
            if deleted_location_count > 0:
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    f"Bulk delete of {deleted_location_count} locations was successful.",
                    extra_tags="alert-success",
                )
        elif locations_to_update:
            # If a product_id is provided, check user authorization for mitigation on that product
            if product_id is not None:
                product = get_object_or_404(Product, id=product_id)
                user_has_permission_or_403(request.user, product, Permissions.Finding_Edit)
            # Filter locations to only those the user is authorized to edit (mitigate)
            locations = get_authorized_locations(Permissions.Location_Edit, locations, request.user)
            skipped_location_count = total_location_count - locations.count()
            updated_location_count = locations.count()
            # Notify user if any locations were skipped due to lack of authorization
            if skipped_location_count > 0:
                add_error_message_to_response(
                    f"Skipped mitigation of {skipped_location_count} locations because you are not authorized.",
                )

            # Bulk update the status of related FindingLocationStatus and ProductLocationStatus objects to 'Mitigated'
            finding_update_counts = LocationFindingReference.objects.filter(location__in=locations).update(
                status=FindingLocationStatus.Mitigated,
                auditor=request.user,
                audit_time=timezone.now(),
            )
            product_update_counts = LocationProductReference.objects.filter(location__in=locations).update(
                status=ProductLocationStatus.Mitigated,
            )
            # Total number of updated statuses for reporting
            update_count = finding_update_counts + product_update_counts
            # Add a success message if any locations were mitigated
            if updated_location_count > 0:
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    f"Bulk mitigation of {updated_location_count} locations ({update_count} endpoint statuses) was successful.",
                    extra_tags="alert-success",
                )
        else:
            # If no endpoints were selected for bulk update, show an error message
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to process bulk update. Required fields were not selected.",
                extra_tags="alert-danger",
            )
    return HttpResponseRedirect(reverse("endpoint", args=()))


@user_is_authorized(Finding, Permissions.Finding_Edit, "finding_id")
def finding_location_bulk_update(request, finding_id):
    if request.method == "POST":
        # Get the list of endpoint IDs to update and the statuses to enable
        finding_locations_to_update = request.POST.getlist("endpoints_to_update")
        status_list = FindingLocationStatus.values
        enable = [item for item in status_list if item in list(request.POST.keys())]
        # Check that endpoints and statuses are selected before proceeding
        if finding_locations_to_update and len(enable) > 0:
            # Iterate over selected locations and update their finding location references
            for location in Location.objects.filter(id__in=finding_locations_to_update):
                finding_location = LocationFindingReference.objects.get(location=location, finding__id=finding_id)
                for status in status_list:
                    # Set the status attribute based on whether it is enabled in the POST request
                    if status in enable:
                        # Enable this status
                        finding_location.__setattr__(status, True)  # noqa: PLC2801
                        # If the status is 'Mitigated', record the auditor and audit time
                        if status == FindingLocationStatus.Mitigated:
                            finding_location.auditor = request.user
                            finding_location.audit_time = timezone.now()
                    else:
                        # Disable this status
                        finding_location.__setattr__(status, False)  # noqa: PLC2801
                finding_location.save()
            # Add a success message after bulk editing endpoints
            messages.add_message(
                request,
                messages.SUCCESS,
                "Bulk edit of endpoints was successful. Check to make sure it is what you intended.",
                extra_tags="alert-success",
            )
        else:
            # If no endpoints or statuses were selected for bulk update, show an error message
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to process bulk update. Required fields were not selected.",
                extra_tags="alert-danger",
            )
    return redirect(request, request.POST["return_url"])


def migrate_endpoints_view(request):
    # Only superusers are allowed to perform endpoint migration
    if not request.user.is_superuser:
        raise PermissionDenied
    view_name = "Migrate endpoints"
    # Attempt to run the endpoint migration management command and handle success or failure
    if request.method == "POST":
        try:
            call_command("migrate_endpoints_to_locations")
            messages.add_message(
                request,
                messages.SUCCESS,
                "Endpoint migration completed successfully.",
                extra_tags="alert-success",
            )
        except Exception as e:
            logger.exception("Error during endpoint migration")
            messages.add_message(
                request,
                messages.ERROR,
                f"Endpoint migration failed: {e}",
                extra_tags="alert-danger",
            )

    return render(
        request, "dojo/migrate_endpoints.html", {
            "name": view_name,
        })


@user_is_authorized(Location, Permissions.Location_View, "location_id")
def endpoint_report(request, location_id):
    location = get_object_or_404(Location, id=location_id)
    return generate_report(request, location, host_view=False)


@user_is_authorized(Location, Permissions.Location_View, "location_id")
def endpoint_host_report(request, location_id):
    location = get_object_or_404(Location, id=location_id)
    return generate_report(request, location, host_view=True)
