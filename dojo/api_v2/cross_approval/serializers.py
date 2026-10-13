from datetime import datetime

from rest_framework import serializers

from dojo.api_v2.cross_approval.models import (
    CrossApprovalDiscussion,
    CrossApprovalExclusion,
    CrossApprovalRequest,
    CrossApprovalRequestLog,
)
from dojo.api_v2.serializers import UserStubSerializer
from dojo.models import GeneralSettings


CROSS_APPROVAL_CSV_SEPARATOR = ","
CROSS_APPROVAL_DEFAULT_WHERE = "all"
CROSS_APPROVAL_MULTI_VALUE_FIELDS = ("where", "priority", "severity")
CROSS_APPROVAL_WHERE_OPTIONS_SETTING_KEY = "DEVSECOPS_ADOPTION_INCLUDE_TAGS"


def parse_cross_approval_date(value):
    if isinstance(value, str):
        for date_format in ("%d%m%Y", "%Y-%m-%d"):
            try:
                return datetime.strptime(value, date_format).date()
            except ValueError:
                continue
    raise serializers.ValidationError("Use DDMMYYYY or YYYY-MM-DD for dates.")


def _exclusion_value(exclusion, field_name):
    if isinstance(exclusion, dict):
        return exclusion.get(field_name)
    return getattr(exclusion, field_name)


def _normalized_multi_values(value, all_is_empty=False):
    if isinstance(value, str):
        values = value.split(CROSS_APPROVAL_CSV_SEPARATOR)
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        values = []

    normalized_values = {
        item.strip().casefold()
        for item in values
        if isinstance(item, str) and item.strip()
    }
    if all_is_empty and normalized_values == {CROSS_APPROVAL_DEFAULT_WHERE}:
        return ()
    return tuple(sorted(normalized_values))


def _exclusion_identity(exclusion):
    return (
        _exclusion_value(exclusion, "vulnerability_id"),
        (_exclusion_value(exclusion, "component_type") or "").strip().casefold(),
        _normalized_multi_values(_exclusion_value(exclusion, "component_values")),
        _normalized_multi_values(_exclusion_value(exclusion, "where"), all_is_empty=True),
        _exclusion_value(exclusion, "create_date"),
        _exclusion_value(exclusion, "expired_date"),
        _normalized_multi_values(_exclusion_value(exclusion, "priority")),
        _normalized_multi_values(_exclusion_value(exclusion, "severity")),
        _exclusion_value(exclusion, "hu"),
        _exclusion_value(exclusion, "reason"),
    )


def _existing_exclusions_by_identity(owner, exclusions, exclude_request_id=None):
    vulnerability_ids = {
        _exclusion_value(exclusion, "vulnerability_id")
        for exclusion in exclusions
    }
    if not vulnerability_ids:
        return {}

    queryset = CrossApprovalExclusion.objects.filter(
        vulnerability_id__in=vulnerability_ids,
        request__owner=owner,
    ).select_related("request")
    if exclude_request_id:
        queryset = queryset.exclude(request_id=exclude_request_id)

    existing_exclusions = {}
    for exclusion in queryset:
        existing_exclusions.setdefault(_exclusion_identity(exclusion), exclusion)
    return existing_exclusions


def find_identical_exclusion(owner, exclusion, exclude_request_id=None):
    identity = _exclusion_identity(exclusion)
    return _existing_exclusions_by_identity(
        owner,
        [exclusion],
        exclude_request_id,
    ).get(identity)


class CrossApprovalExclusionSerializer(serializers.ModelSerializer):
    exclusion_id = serializers.IntegerField(source="pk", read_only=True)
    id = serializers.CharField(source="vulnerability_id")
    where = serializers.CharField(default=CROSS_APPROVAL_DEFAULT_WHERE, allow_blank=True, required=False)
    component_type = serializers.CharField(default="image", required=False)
    component_values = serializers.ListField(
        child=serializers.CharField(), min_length=1, required=False
    )
    create_date = serializers.CharField()
    expired_date = serializers.CharField()

    class Meta:
        model = CrossApprovalExclusion
        fields = (
            "exclusion_id", "id", "where", "create_date", "expired_date", "expired_at", "priority",
            "severity", "hu", "reason", "component_type", "component_values",
        )
        read_only_fields = ("expired_at",)

    def to_internal_value(self, data):
        data = data.copy()
        if "cve_id" in data and "id" not in data:
            data["id"] = data["cve_id"]
        if "id" in data and "cve_id" in data and data["id"] != data["cve_id"]:
            raise serializers.ValidationError(
                {"cve_id": "cve_id must match id when both are provided."}
            )

        component = data.get("component")
        if isinstance(component, dict):
            if "type" in component:
                data["component_type"] = component["type"]
            if "values" in component:
                data["component_values"] = component["values"]

        for field_name in CROSS_APPROVAL_MULTI_VALUE_FIELDS:
            if field_name in data:
                data[field_name] = self._csv_from_value(data[field_name])

        return super().to_internal_value(data)

    def validate_create_date(self, value):
        return parse_cross_approval_date(value)

    def validate_where(self, value):
        normalized_where = self._normalize_where(value)
        if normalized_where == CROSS_APPROVAL_DEFAULT_WHERE:
            return normalized_where

        configured_where_options = self._configured_where_options()
        where_values = self._csv_values(normalized_where)
        invalid_values = [
            where_value
            for where_value in where_values
            if where_value.casefold() not in configured_where_options
        ]
        if invalid_values:
            raise serializers.ValidationError(
                f"where contains unsupported value(s): {', '.join(invalid_values)}."
            )

        return normalized_where

    def validate_priority(self, value):
        return self._csv_from_value(value)

    def validate_severity(self, value):
        return self._csv_from_value(value)

    def validate_expired_date(self, value):
        return parse_cross_approval_date(value)

    def validate(self, attrs):
        if attrs["expired_date"] < attrs["create_date"]:
            raise serializers.ValidationError("expired_date must not precede create_date.")

        if not attrs.get("component_values"):
            raise serializers.ValidationError(
                {"component": "component.values must include at least one value."}
            )

        return attrs

    def _normalize_where(self, value):
        normalized_where = self._csv_from_value(value)
        return normalized_where or CROSS_APPROVAL_DEFAULT_WHERE

    def _configured_where_options(self):
        configured_values = GeneralSettings.get_value(
            CROSS_APPROVAL_WHERE_OPTIONS_SETTING_KEY,
            [],
        )
        normalized_values = set()
        for configured_value in self._csv_values(configured_values):
            normalized_values.add(configured_value.casefold())
        return normalized_values

    def _csv_values(self, value):
        if isinstance(value, str):
            raw_items = value.split(CROSS_APPROVAL_CSV_SEPARATOR)
        elif isinstance(value, (list, tuple)):
            raw_items = value
        else:
            raw_items = []

        normalized_items = []
        for raw_item in raw_items:
            if not isinstance(raw_item, str):
                continue
            normalized_item = raw_item.strip()
            if normalized_item and normalized_item not in normalized_items:
                normalized_items.append(normalized_item)

        return normalized_items

    def _csv_from_value(self, value):
        return CROSS_APPROVAL_CSV_SEPARATOR.join(self._csv_values(value))

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["create_date"] = instance.create_date.strftime("%d%m%Y")
        data["expired_date"] = instance.expired_date.strftime("%d%m%Y")
        data["cve_id"] = data["id"]
        component_type = data.pop("component_type")
        component_values = data.pop("component_values")
        data["component"] = {
            "type": component_type,
            "values": component_values,
        }

        return data


class CrossApprovalRequestSerializer(serializers.ModelSerializer):
    created_by = UserStubSerializer(read_only=True)
    status_updated_by = UserStubSerializer(read_only=True)
    exclusions = CrossApprovalExclusionSerializer(many=True)
    owner = serializers.CharField(required=True)
    discussions = serializers.SerializerMethodField()
    logs = serializers.SerializerMethodField()

    class Meta:
        model = CrossApprovalRequest
        fields = (
            "id", "owner", "status", "created_at", "created_by", "status_updated_by",
            "status_updated_at", "exclusions", "discussions", "logs",
        )
        read_only_fields = (
            "id", "status", "created_at", "created_by", "status_updated_by",
            "status_updated_at",
        )

    def validate(self, attrs):
        exclusions = attrs.get("exclusions", [])
        owner = attrs.get("owner") or (self.instance.owner if self.instance else None)
        exclusion_identities = [_exclusion_identity(exclusion) for exclusion in exclusions]
        if len(exclusion_identities) != len(set(exclusion_identities)):
            raise serializers.ValidationError({
                "exclusions": "An identical exclusion is duplicated in this request.",
            })

        existing_exclusions = _existing_exclusions_by_identity(
            owner,
            exclusions,
            self.instance.pk if self.instance else None,
        )
        conflict = next(
            (
                existing_exclusions[identity]
                for identity in exclusion_identities
                if identity in existing_exclusions
            ),
            None,
        )
        if conflict:
            raise serializers.ValidationError({
                "exclusions": (
                    f"An identical exclusion for Vulnerability ID {conflict.vulnerability_id} "
                    "already exists for this owner."
                ),
            })
        return attrs

    def create(self, validated_data):
        exclusions = validated_data.pop("exclusions")
        request = CrossApprovalRequest.objects.create(
            created_by=self.context["request"].user, **validated_data
        )
        CrossApprovalExclusion.objects.bulk_create(
            [CrossApprovalExclusion(request=request, **exclusion) for exclusion in exclusions]
        )
        return request

    def get_discussions(self, instance):
        return CrossApprovalDiscussionSerializer(
            instance.discussions.all(), many=True, context=self.context
        ).data

    def get_logs(self, instance):
        return CrossApprovalRequestLogSerializer(instance.logs.all(), many=True).data

    def update(self, instance, validated_data):
        exclusions = validated_data.pop("exclusions", None)
        if exclusions is not None:
            instance.exclusions.all().delete()
            CrossApprovalExclusion.objects.bulk_create(
                [CrossApprovalExclusion(request=instance, **exclusion) for exclusion in exclusions]
            )
        instance.owner = validated_data.get("owner", instance.owner)
        instance.save(update_fields=["owner"])
        return instance


class CrossApprovalDiscussionSerializer(serializers.ModelSerializer):
    author = UserStubSerializer(read_only=True)
    is_mine = serializers.SerializerMethodField()

    class Meta:
        model = CrossApprovalDiscussion
        fields = ("id", "author", "content", "created_at", "updated_at", "is_mine")
        read_only_fields = ("id", "author", "created_at", "updated_at", "is_mine")

    def get_is_mine(self, instance):
        request = self.context.get("request")
        return bool(request and request.user == instance.author)


class CrossApprovalRequestLogSerializer(serializers.ModelSerializer):
    changed_by = UserStubSerializer(read_only=True)

    class Meta:
        model = CrossApprovalRequestLog
        fields = ("id", "previous_status", "current_status", "changed_by", "changed_at")