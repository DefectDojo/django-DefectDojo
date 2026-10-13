from django.db import transaction
from django.utils import timezone
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from dojo.api_v2.mixins import DeletePreviewModelMixin
from dojo.api_v2.cross_approval.helpers import (
    apply_request_exclusions,
    expire_cross_approval_exclusion,
    expire_request_exclusions,
    log_status_change,
    notify_request_status,
    reopen_cross_approval_exclusion,
    revert_cross_approval_exclusion,
)
from dojo.api_v2.cross_approval.models import CrossApprovalDiscussion, CrossApprovalExclusion, CrossApprovalRequest
from dojo.api_v2.cross_approval.permissions import IsCrossApprovalReviewer, IsCrossApprovalSubmitter
from dojo.api_v2.cross_approval.serializers import (
    CrossApprovalExclusionSerializer,
    CrossApprovalDiscussionSerializer,
    CrossApprovalRequestSerializer,
    find_identical_exclusion,
)
from dojo.models import GeneralSettings


class CrossApprovalRequestViewSet(DeletePreviewModelMixin, ModelViewSet):
    queryset = CrossApprovalRequest.objects.select_related(
        "created_by", "status_updated_by"
    ).prefetch_related("exclusions", "discussions__author", "logs__changed_by")
    serializer_class = CrossApprovalRequestSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = super().get_queryset()
        request_id = self.request.query_params.get("id") if self.request else None
        vulnerability_id = self.request.query_params.get("cve") if self.request else None
        status = self.request.query_params.get("status") if self.request else None
        owner = self.request.query_params.get("owner") if self.request else None

        if request_id:
            queryset = queryset.filter(pk=request_id) if request_id.isdigit() else queryset.none()
        if vulnerability_id:
            queryset = queryset.filter(exclusions__vulnerability_id__icontains=vulnerability_id)
        if status:
            queryset = queryset.filter(status=status)
        if owner:
            queryset = queryset.filter(owner__icontains=owner)
        return queryset.distinct()

    def get_permissions(self):
        if self.action in {"approve", "reject"}:
            return [IsAuthenticated(), IsCrossApprovalReviewer()]
        if self.action in {"create", "update", "partial_update", "destroy", "expire", "expire_exclusion", "reopen_exclusion"}:
            return [IsAuthenticated(), IsCrossApprovalSubmitter()]
        return super().get_permissions()

    def perform_create(self, serializer):
        instance = serializer.save()
        notify_request_status(
            instance,
            "cross_approval_created",
            f"Cross-approval request {instance.pk} created",
        )

    @action(detail=False, methods=["get", "post"], url_path="validate-vulnerability-id")
    def validate_vulnerability_id(self, request):
        exclusion = None
        if request.method == "POST":
            owner_value = request.data.get("owner", "")
            owner = owner_value.strip() if isinstance(owner_value, str) else ""
            exclusion_data = request.data.get("exclusion")
            if not isinstance(exclusion_data, dict):
                return Response({"detail": "exclusion is required."}, status=400)
            exclusion_serializer = CrossApprovalExclusionSerializer(data=exclusion_data)
            exclusion_serializer.is_valid(raise_exception=True)
            exclusion = exclusion_serializer.validated_data
            vulnerability_id = exclusion["vulnerability_id"]
        else:
            vulnerability_id = request.query_params.get("vulnerability_id", "").strip()
            owner = request.query_params.get("owner", "").strip()
            if not vulnerability_id:
                return Response({"detail": "vulnerability_id is required."}, status=400)
        if not owner:
            return Response({"detail": "owner is required."}, status=400)

        if exclusion is not None:
            exclude_request_id = request.data.get("exclude_request_id")
            conflict = find_identical_exclusion(owner, exclusion, exclude_request_id)
            conflicts = [] if not conflict else [{
                "request_id": conflict.request_id,
                "status": conflict.request.status,
            }]
        else:
            exclusions = CrossApprovalExclusion.objects.filter(
                vulnerability_id=vulnerability_id,
                request__owner=owner,
            ).select_related("request")
            exclude_request_id = request.query_params.get("exclude_request_id")
            if exclude_request_id:
                exclusions = exclusions.exclude(request_id=exclude_request_id)
            conflicts = [
                {"request_id": exclusion.request_id, "status": exclusion.request.status}
                for exclusion in exclusions
            ]
        return Response({"vulnerability_id": vulnerability_id, "conflicts": conflicts})

    @action(detail=False, methods=["get"], url_path="owners")
    def owners(self, request):
        configured_owners = GeneralSettings.get_value(
            "CROSS_APPROVAL_AVAILABLE_OWNERS", ["x86", "ace"]
        )
        return Response({
            "owners": self._normalize_general_settings_list(
                configured_owners,
                ["x86", "ace"],
            ),
        })

    @action(detail=False, methods=["get"], url_path="where-options")
    def where_options(self, request):
        configured_where_options = GeneralSettings.get_value(
            "DEVSECOPS_ADOPTION_INCLUDE_TAGS", []
        )
        return Response({
            "where_options": self._normalize_general_settings_list(
                configured_where_options,
                [],
            ),
        })

    @action(detail=False, methods=["get"], url_path="components")
    def components(self, request):
        summaries = {}
        component_value_filter = request.query_params.get("component_value", "").strip().casefold()
        component_type_filter = request.query_params.get("component_type", "").strip().casefold()
        owner_filter = request.query_params.get("owner", "").strip().casefold()
        queryset = self.filter_queryset(self.get_queryset()).filter(status="approved").prefetch_related("exclusions")
        today = timezone.localdate()
        for cross_approval_request in queryset:
            if not self._request_owner_matches(cross_approval_request, owner_filter):
                continue
            self._collect_request_component_summaries(
                summaries,
                cross_approval_request,
                today,
                component_type_filter,
                component_value_filter,
            )
        response = self._components_response(summaries)
        page = self.paginate_queryset(response)
        if page is not None:
            return self.get_paginated_response(page)
        return Response(response)

    def _request_owner_matches(self, cross_approval_request, owner_filter):
        request_owner = (cross_approval_request.owner or "").strip().casefold()
        return not owner_filter or owner_filter in request_owner

    def _normalize_general_settings_list(self, configured_values, default_values):
        if isinstance(configured_values, str):
            values = configured_values.split(",")
        elif isinstance(configured_values, (list, tuple)):
            values = configured_values
        else:
            values = []

        normalized_values = []
        for value in values:
            normalized_value = value.strip() if isinstance(value, str) else ""
            if normalized_value and normalized_value not in normalized_values:
                normalized_values.append(normalized_value)

        return normalized_values or default_values

    def _collect_request_component_summaries(
        self,
        summaries,
        cross_approval_request,
        today,
        component_type_filter,
        component_value_filter,
    ):
        for exclusion in cross_approval_request.exclusions.all():
            if not self._is_active_exclusion(exclusion, today):
                continue
            component_type = exclusion.component_type.casefold()
            if component_type_filter and component_type != component_type_filter:
                continue
            for component_value in self._matching_component_values(exclusion, component_value_filter):
                self._add_component_summary(
                    summaries,
                    cross_approval_request,
                    exclusion,
                    component_type,
                    component_value,
                )

    def _is_active_exclusion(self, exclusion, today):
        return not exclusion.expired_at and exclusion.expired_date >= today

    def _matching_component_values(self, exclusion, component_value_filter):
        component_values = set(exclusion.component_values or [])
        if not component_value_filter:
            return component_values
        return [
            component_value
            for component_value in component_values
            if component_value_filter in component_value.casefold()
        ]

    def _add_component_summary(self, summaries, cross_approval_request, exclusion, component_type, component_value):
        request_owner = cross_approval_request.owner
        summary_key = (request_owner, component_type, component_value)
        summary = summaries.setdefault(
            summary_key,
            {
                "owner": request_owner,
                "component": {
                    "type": component_type,
                    "values": [component_value],
                },
                "added_date": None,
                "exclusion_count": 0,
                "vulnerability_exclusions": {},
            },
        )
        exclusion_create_date = getattr(exclusion, "create_date", None)
        if exclusion_create_date and (
            summary["added_date"] is None
            or exclusion_create_date < summary["added_date"]
        ):
            summary["added_date"] = exclusion_create_date
        summary["exclusion_count"] += 1
        vulnerability_id = exclusion.vulnerability_id
        vulnerability_summary = summary["vulnerability_exclusions"].setdefault(
            vulnerability_id,
            {"vulnerability_id": vulnerability_id, "exclusions": []},
        )
        vulnerability_summary["exclusions"].append(
            CrossApprovalExclusionSerializer(exclusion).data
        )

    def _components_response(self, summaries):
        return [
            {
                **{
                    **summary,
                    "added_date": (
                        summary["added_date"].strftime("%d%m%Y")
                        if summary["added_date"]
                        else None
                    ),
                },
                "vulnerability_exclusions": list(summary["vulnerability_exclusions"].values()),
            }
            for _, summary in sorted(summaries.items(), key=lambda item: item[0])
        ]

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        return self._set_status(request, "approved")

    @action(detail=True, methods=["post"])
    def reject(self, request, pk=None):
        return self._set_status(request, "rejected")

    @action(detail=True, methods=["post"])
    def expire(self, request, pk=None):
        instance = self.get_object()
        if instance.status != "approved":
            return Response({"detail": "Only approved requests can expire exclusions."}, status=400)
        expire_request_exclusions(instance)
        notify_request_status(
            instance,
            "cross_approval_expired",
            f"Cross-approval request {instance.pk} expired",
        )
        return Response(self.get_serializer(instance).data)

    @action(detail=True, methods=["post"], url_path="expire-exclusion")
    def expire_exclusion(self, request, pk=None):
        instance = self.get_object()
        if instance.status != "approved":
            return Response({"detail": "Only exclusions on approved requests can expire."}, status=400)
        exclusion_id = request.data.get("exclusion_id")
        exclusion = instance.exclusions.filter(pk=exclusion_id).first()
        if not exclusion:
            return Response({"detail": "Exclusion not found on this request."}, status=404)
        expire_cross_approval_exclusion(exclusion, request.user)
        notify_request_status(
            instance,
            "cross_approval_expired",
            f"Cross-approval request {instance.pk} exclusion expired",
        )
        return Response(self.get_serializer(self.get_object()).data)

    @action(detail=True, methods=["post"], url_path="reopen-exclusion")
    def reopen_exclusion(self, request, pk=None):
        instance = self.get_object()
        if instance.status != "approved":
            return Response({"detail": "Only exclusions on approved requests can reopen."}, status=400)
        exclusion = instance.exclusions.filter(pk=request.data.get("exclusion_id")).first()
        if not exclusion:
            return Response({"detail": "Exclusion not found on this request."}, status=404)
        if not reopen_cross_approval_exclusion(exclusion, request.user):
            return Response({"detail": "Only manually expired, non-expired exclusions can reopen."}, status=400)
        notify_request_status(
            instance,
            "cross_approval_reopened",
            f"Cross-approval request {instance.pk} exclusion reopened",
        )
        return Response(self.get_serializer(self.get_object()).data)

    @action(detail=True, methods=["get", "post"])
    def discussions(self, request, pk=None):
        instance = self.get_object()
        if request.method == "POST" and request.user != instance.created_by and not IsCrossApprovalReviewer().has_permission(request, self):
            return Response({"detail": "Only the requester or a maintainer can access discussions."}, status=403)
        if request.method == "GET":
            return Response(CrossApprovalDiscussionSerializer(
                instance.discussions.all(), many=True, context={"request": request}
            ).data)
        serializer = CrossApprovalDiscussionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        discussion = serializer.save(request=instance, author=request.user)
        notify_request_status(instance, "cross_approval_discussion", f"New discussion on cross-approval request {instance.pk}")
        return Response(
            CrossApprovalDiscussionSerializer(discussion, context={"request": request}).data,
            status=201,
        )

    def _set_status(self, request, status):
        instance = self.get_object()
        if instance.status != "pending":
            return Response({"detail": "Only pending requests can be decided."}, status=400)
        previous_status = instance.status
        instance.status = status
        instance.status_updated_by = request.user
        instance.status_updated_at = timezone.now()
        instance.save(update_fields=["status", "status_updated_by", "status_updated_at"])
        log_status_change(instance, request.user, previous_status, status)
        if status == "approved":
            apply_request_exclusions(instance)
        status_event = {
            "approved": "cross_approval_approved",
            "rejected": "cross_approval_rejected",
        }[status]
        notify_request_status(instance, status_event, f"Cross-approval request {instance.pk} {status}")
        return Response(self.get_serializer(instance).data)

    def perform_destroy(self, instance):
        with transaction.atomic():
            if instance.status == "approved":
                for exclusion in instance.exclusions.all():
                    revert_cross_approval_exclusion(
                        exclusion,
                        exclude_request_id=instance.pk,
                    )
            notify_request_status(
                instance,
                "cross_approval_deleted",
                f"Cross-approval request {instance.pk} deleted",
            )
            instance.delete()