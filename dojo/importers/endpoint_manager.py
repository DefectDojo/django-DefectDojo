import logging

from django.core.exceptions import MultipleObjectsReturned, ValidationError
from django.urls import reverse
from django.utils import timezone

from dojo.celery import app
from dojo.decorators import dojo_async_task
from dojo.endpoint.utils import endpoint_get_or_create
from dojo.models import (
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    Finding,
)

logger = logging.getLogger(__name__)


class EndpointManager:
    @dojo_async_task
    @app.task()
    def add_endpoints_to_unsaved_finding(
        self,
        finding: Finding,
        endpoints: list[Endpoint],
        **kwargs: dict,
    ) -> None:
        """Creates Endpoint objects for a single finding and creates the link via the endpoint status"""
        logger.debug(f"IMPORT_SCAN: Adding {len(endpoints)} endpoints to finding: {finding}")
        self.clean_unsaved_endpoints(endpoints)
        for endpoint in endpoints:
            ep = None
            try:
                ep, _ = endpoint_get_or_create(
                    protocol=endpoint.protocol,
                    userinfo=endpoint.userinfo,
                    host=endpoint.host,
                    port=endpoint.port,
                    path=endpoint.path,
                    query=endpoint.query,
                    fragment=endpoint.fragment,
                    product=finding.test.engagement.product)
            except (MultipleObjectsReturned):
                msg = (
                    f"Endpoints in your database are broken. "
                    f"Please access {reverse('endpoint_migrate')} and migrate them to new format or remove them."
                )
                raise Exception(msg)

            Endpoint_Status.objects.get_or_create(
                finding=finding,
                endpoint=ep,
                defaults={"date": finding.date})
        logger.debug(f"IMPORT_SCAN: {len(endpoints)} imported")
        return

    @dojo_async_task
    @app.task()
    def mitigate_endpoint_status(
        self,
        endpoint_status_list: list[Endpoint_Status],
        user: Dojo_User,
        **kwargs: dict,
    ) -> None:
        """Mitigates all endpoint status objects that are supplied"""
        now = timezone.now()
        for endpoint_status in endpoint_status_list:
            # Only mitigate endpoints that are actually active
            if endpoint_status.mitigated is False:
                endpoint_status.mitigated_time = now
                endpoint_status.last_modified = now
                endpoint_status.mitigated_by = user
                endpoint_status.mitigated = True
                endpoint_status.save()
        return

    @dojo_async_task
    @app.task()
    def reactivate_endpoint_status(
        self,
        endpoint_status_list: list[Endpoint_Status],
        **kwargs: dict,
    ) -> None:
        """Reactivate all endpoint status objects that are supplied"""
        for endpoint_status in endpoint_status_list:
            # Only reactivate endpoints that are actually mitigated
            if endpoint_status.mitigated:
                logger.debug("Re-import: reactivating endpoint %s that is present in this scan", str(endpoint_status.endpoint))
                endpoint_status.mitigated_by = None
                endpoint_status.mitigated_time = None
                endpoint_status.mitigated = False
                endpoint_status.last_modified = timezone.now()
                endpoint_status.save()
        return

    def chunk_endpoints_and_disperse(
        self,
        finding: Finding,
        endpoints: list[Endpoint],
        **kwargs: dict,
    ) -> None:
        self.add_endpoints_to_unsaved_finding(finding, endpoints, sync=True)
        return

    def clean_unsaved_endpoints(
        self,
        endpoints: list[Endpoint],
    ) -> None:
        """
        Clean endpoints that are supplied. For any endpoints that fail this validation
        process, raise a message that broken endpoints are being stored
        """
        for endpoint in endpoints:
            try:
                endpoint.clean()
            except ValidationError as e:
                logger.warning(f"DefectDojo is storing broken endpoint because cleaning wasn't successful: {e}")
        return

    def chunk_endpoints_and_reactivate(
        self,
        endpoint_status_list: list[Endpoint_Status],
        **kwargs: dict,
    ) -> None:
        self.reactivate_endpoint_status(endpoint_status_list, sync=True)
        return

    def chunk_endpoints_and_mitigate(
        self,
        endpoint_status_list: list[Endpoint_Status],
        user: Dojo_User,
        **kwargs: dict,
    ) -> None:
        self.mitigate_endpoint_status(endpoint_status_list, user, sync=True)
        return

    def update_endpoint_status(
        self,
        existing_finding: Finding,
        new_finding: Finding,
        user: Dojo_User,
        **kwargs: dict,
    ) -> None:
        """Update the list of endpoints from the new finding with the list that is in the old finding"""
        # New endpoints are already added in serializers.py / views.py (see comment "# for existing findings: make sure endpoints are present or created")
        # So we only need to mitigate endpoints that are no longer present
        # using `.all()` will mark as mitigated also `endpoint_status` with flags `false_positive`, `out_of_scope` and `risk_accepted`. This is a known issue. This is not a bug. This is a future.
        existing_finding_endpoint_status_list = existing_finding.status_finding.all()
        new_finding_endpoints_list = new_finding.unsaved_endpoints
        if new_finding.is_mitigated:
            # New finding is mitigated, so mitigate all old endpoints
            endpoint_status_to_mitigate = existing_finding_endpoint_status_list
        else:
            # Mitigate any endpoints in the old finding not found in the new finding
            endpoint_status_to_mitigate = list(
                filter(
                    lambda existing_finding_endpoint_status: existing_finding_endpoint_status.endpoint not in new_finding_endpoints_list,
                    existing_finding_endpoint_status_list),
            )
            # Re-activate any endpoints in the old finding that are in the new finding
            endpoint_status_to_reactivate = list(
                filter(
                    lambda existing_finding_endpoint_status: existing_finding_endpoint_status.endpoint in new_finding_endpoints_list,
                    existing_finding_endpoint_status_list),
            )
            self.chunk_endpoints_and_reactivate(endpoint_status_to_reactivate)
        self.chunk_endpoints_and_mitigate(endpoint_status_to_mitigate, user)
        return
