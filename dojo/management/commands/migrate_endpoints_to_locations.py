import logging

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand

from dojo.location.models import Location
from dojo.location.status import FindingLocationStatus
from dojo.models import DojoMeta, Endpoint, Endpoint_Status
from dojo.url.models import URL
from dojo.url.validators import validate_host_or_ip

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    """
    This management command creates a mapping from Endpoints and Endpoint Statuses to a new Locations system.
    The following occurs:
    - Endpoints -> URL (which will create a Location)
    - Products on Endpoint -> LocationProductReference
    - Findings on Endpoints -> LocationProductReference
    """

    help = "Usage: manage.py migrate_endpoints_to_locations"

    def _endpoint_to_url(self, endpoint: Endpoint) -> Location:
        # First determine if we will have a problem with the endpoint
        try:
            validate_host_or_ip(endpoint.host)
            host_validation_failure = False
        except ValidationError:
            host_validation_failure = True
        # Create the raw URL object first
        # This should create the location object as well
        url = URL.objects.get_or_create(
            protocol=endpoint.protocol or "tcp",
            user_info=endpoint.userinfo or "",
            host=endpoint.host,
            port=endpoint.port,
            path=endpoint.path or "/",
            query=endpoint.query or "",
            fragment=endpoint.fragment or "",
            host_validation_failure=host_validation_failure,
        )[0]
        # Add the endpoint tags to the location tags
        if endpoint.tags:
            [url.location.tags.add(tag) for tag in set(endpoint.tags.values_list("name", flat=True))]
        # Add any metadata from the endpoint to the location
        for meta in endpoint.endpoint_meta.all():
            DojoMeta.objects.get_or_create(
                name=meta.name,
                value=meta.value,
                location=url.location,
            )

        return url.location

    def _convert_endpoint_status_to_string_status(self, endpoint_status: Endpoint_Status) -> str:
        """
        Start the conversion with the "special" statuses first since we are moving to a model
        of having a single status possible rather than a combo of many
        """
        if endpoint_status.risk_accepted:
            return FindingLocationStatus.RiskExcepted
        if endpoint_status.false_positive:
            return FindingLocationStatus.FalsePositive
        if endpoint_status.out_of_scope:
            return FindingLocationStatus.OutOfScope
        if endpoint_status.mitigated:
            return FindingLocationStatus.Mitigated
        # Default to Active
        return FindingLocationStatus.Active

    def _associate_location_with_findings(self, endpoint: Endpoint, location: Location) -> None:
        # Determine if we can associate from the finding, or if have to use the product (for cases of zero findings on an endpoint)
        if endpoint.status_endpoint.exists():
            # Iterate over each endpoint status to get the status and the finding object
            for endpoint_status in endpoint.status_endpoint.all():
                if finding := endpoint_status.finding:
                    # Determine the status of the location based on the status of the endpoint status
                    status = self._convert_endpoint_status_to_string_status(endpoint_status)
                    # Create the association (which will also associate with the product)
                    location.associate_with_finding(
                        finding=finding,
                        status=status,
                        auditor=endpoint_status.mitigated_by,
                        audit_time=endpoint_status.mitigated_time,
                    )
        elif product := endpoint.product:
            location.associate_with_product(product)

    def handle(self, *args, **options):
        # Start off with the endpoint objects - it should everything we need
        for endpoint in Endpoint.objects.all().iterator():
            # Get the URL object first
            location = self._endpoint_to_url(endpoint)
            # Associate the URL with the findings associated with the Findings
            # the association to a finding will also apply to a product automatically
            self._associate_location_with_findings(endpoint, location)
