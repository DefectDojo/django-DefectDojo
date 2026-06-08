import json
import logging
import re
import time
from datetime import datetime

import six
import tagulous
from django.conf import settings
from django.contrib.auth.models import Permission
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.utils import IntegrityError
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers
from rest_framework.exceptions import NotFound
from rest_framework.exceptions import ValidationError as RestFrameworkValidationError

import dojo.risk_acceptance.helper as ra_helper
from dojo.endpoint.utils import endpoint_filter, endpoint_meta_import
from dojo.finding.queries import get_authorized_findings
from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.importers.base_importer import BaseImporter
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.location.models import Location
from dojo.models import (
    IMPORT_ACTIONS,
    SEVERITIES,
    SEVERITY_CHOICES,
    STATS_FIELDS,
    Announcement,
    App_Analysis,
    Development_Environment,
    DojoMeta,
    Endpoint,
    Endpoint_Params,
    Endpoint_Status,
    Engagement,
    FileUpload,
    Finding,
    Finding_Group,
    Language_Type,
    Languages,
    Network_Locations,
    Note_Type,
    NoteHistory,
    Notes,
    Product,
    Product_API_Scan_Configuration,
    Regulation,
    Risk_Acceptance,
    SLA_Configuration,
    Sonarqube_Issue,
    Sonarqube_Issue_Transition,
    Test,
    Tool_Configuration,
    Tool_Product_Settings,
    Tool_Type,
    User,
    get_current_date,
)
from dojo.product_announcements import (
    LargeScanSizeProductAnnouncement,
    ScanTypeProductAnnouncement,
)
from dojo.tools.factory import (
    get_choices_sorted,
    requires_file,
    requires_tool_type,
)
from dojo.utils import is_scan_file_too_large
from dojo.validators import ImporterFileExtensionValidator, tag_validator

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


def get_product_id_from_dict(data):
    product_id = data.get("product", None)
    if product_id:
        if isinstance(product_id, Product):
            product_id = product_id.id
        elif isinstance(product_id, str) and not product_id.isdigit():
            msg = "product must be an integer"
            raise serializers.ValidationError(msg)
    return product_id


class StatusStatisticsSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for stat in STATS_FIELDS:
            self.fields[stat.lower()] = serializers.IntegerField()


class SeverityStatusStatisticsSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for sev in SEVERITIES:
            self.fields[sev.lower()] = StatusStatisticsSerializer()

        self.fields["total"] = StatusStatisticsSerializer()


class DeltaStatisticsSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for action in IMPORT_ACTIONS:
            self.fields[
                action[1].lower()
            ] = SeverityStatusStatisticsSerializer()


class ImportStatisticsSerializer(serializers.Serializer):
    before = SeverityStatusStatisticsSerializer(
        required=False,
        help_text="Finding statistics as stored in Defect Dojo before the import",
    )
    delta = DeltaStatisticsSerializer(
        required=False,
        help_text="Finding statistics of modifications made by the reimport. Only available when TRACK_IMPORT_HISTORY has not been disabled.",
    )
    after = SeverityStatusStatisticsSerializer(
        help_text="Finding statistics as stored in Defect Dojo after the import",
    )


@extend_schema_field(
    serializers.ListField(child=serializers.CharField()),
)  # also takes basic python types
class TagListSerializerField(serializers.ListField):
    child = serializers.CharField()
    default_error_messages = {
        "not_a_list": _(
            'Expected a list of items but got type "{input_type}".',
        ),
        "invalid_json": _(
            "Invalid json list. A tag list submitted in string"
            " form must be valid json.",
        ),
        "not_a_str": _("All list items must be of string type."),
    }
    order_by = None

    def __init__(self, **kwargs):
        pretty_print = kwargs.pop("pretty_print", True)

        style = kwargs.pop("style", {})
        kwargs["style"] = {"base_template": "textarea.html"}
        kwargs["style"].update(style)

        super().__init__(**kwargs)

        self.pretty_print = pretty_print

    def to_internal_value(self, data):
        if isinstance(data, list) and data == [""] and self.allow_empty:
            return []
        if isinstance(data, six.string_types):
            if not data:
                data = []
            try:
                data = json.loads(data)
            except ValueError:
                self.fail("invalid_json")

        logger.debug("data as json: %s", data)

        if not isinstance(data, list):
            self.fail("not_a_list", input_type=type(data).__name__)

        data_safe = []
        for s in data:
            # Ensure if the element in the list is  string
            if not isinstance(s, six.string_types):
                self.fail("not_a_str")
            # Run the children validation
            self.child.run_validation(s)
            # Split the tags up in any way we need to
            substrings = re.findall(r'(?:"[^"]*"|[^",]+)', s)
            # Validate the tag to ensure it doesn't contain invalid characters
            for sub in substrings:
                tag_validator(sub, exception_class=RestFrameworkValidationError)
            data_safe.extend(substrings)

        logger.debug("result after rendering tags: %s", data_safe)
        return data_safe

    def to_representation(self, value):
        if not isinstance(value, list):
            # we can't use isinstance because TagRelatedManager is non-existing class
            # it cannot be imported or referenced, so we fallback to string
            # comparison
            if type(value).__name__ == "TagRelatedManager":
                value = value.get_tag_list()
            elif isinstance(value, str):
                value = tagulous.utils.parse_tags(value)
            else:
                msg = f"unable to convert {type(value).__name__} into list of tags"
                raise ValueError(msg)
        return value


class MetaSerializer(serializers.ModelSerializer):
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    endpoint = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    location = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    finding = serializers.PrimaryKeyRelatedField(
        queryset=Finding.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )

    def validate(self, data):
        if settings.V3_FEATURE_LOCATIONS and "endpoint" in data:
            data["location"] = data.pop("endpoint")
        DojoMeta(**data).clean()
        return data

    # TODO: Delete this after the move to Locations
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not settings.V3_FEATURE_LOCATIONS:
            self.fields["endpoint"] = serializers.PrimaryKeyRelatedField(
                queryset=Endpoint.objects.all(),
                required=False,
                default=None,
                allow_null=True,
            )

    class Meta:
        model = DojoMeta
        fields = "__all__"


class MetadataSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=120)
    value = serializers.CharField(max_length=300)


class MetaMainSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)

    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    endpoint = serializers.PrimaryKeyRelatedField(
        queryset=Endpoint.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    finding = serializers.PrimaryKeyRelatedField(
        queryset=Finding.objects.all(),
        required=False,
        default=None,
        allow_null=True,
    )
    metadata = MetadataSerializer(many=True)

    def validate(self, data):
        product_id = data.get("product", None)
        endpoint_id = data.get("endpoint", None)
        finding_id = data.get("finding", None)
        metadata = data.get("metadata")

        for item in metadata:
            # this will only verify that one and only one of product, endpoint, or finding is passed...
            DojoMeta(product=product_id,
                     endpoint=endpoint_id,
                     finding=finding_id,
                     name=item.get("name"),
                     value=item.get("value")).clean()

        return data


from dojo.user.api.serializer import (  # noqa: E402, F401 -- backward compat + prefetcher discovery
    AddUserSerializer,
    UserContactInfoSerializer,
    UserProfileSerializer,
    UserSerializer,
    UserStubSerializer,
)


class NoteTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note_Type
        fields = "__all__"


class NoteHistorySerializer(serializers.ModelSerializer):
    current_editor = UserStubSerializer(read_only=True)
    note_type = NoteTypeSerializer(read_only=True, many=False)

    class Meta:
        model = NoteHistory
        fields = "__all__"


class NoteSerializer(serializers.ModelSerializer):
    author = UserStubSerializer(many=False, read_only=True)
    editor = UserStubSerializer(read_only=True, many=False, allow_null=True)
    history = NoteHistorySerializer(read_only=True, many=True)
    note_type = NoteTypeSerializer(read_only=True, many=False)

    def update(self, instance, validated_data):
        instance.entry = validated_data.get("entry")
        instance.edited = True
        instance.editor = self.context["request"].user
        instance.edit_time = timezone.now()
        history = NoteHistory(
            data=instance.entry,
            time=instance.edit_time,
            current_editor=instance.editor,
        )
        history.save()
        instance.history.add(history)
        instance.save()
        return instance

    class Meta:
        model = Notes
        fields = "__all__"


class FileSerializer(serializers.ModelSerializer):
    file = serializers.FileField(required=True)

    class Meta:
        model = FileUpload
        fields = "__all__"

    def validate(self, data):
        if file := data.get("file"):
            # the clean will validate the file extensions and raise a Validation error if the extensions are not accepted
            FileUpload(title=file.name, file=file).clean()
            return data
        return None


class RawFileSerializer(serializers.ModelSerializer):
    file = serializers.FileField(required=True)

    class Meta:
        model = FileUpload
        fields = ["file"]


class RiskAcceptanceProofSerializer(serializers.ModelSerializer):
    path = serializers.FileField(required=True)

    class Meta:
        model = Risk_Acceptance
        fields = ["path"]


# Engagement serializers live in dojo/engagement/api/serializer.py.
# EngagementSerializer is re-exported here because ReportGenerateSerializer and
# RiskAcceptanceSerializer (below) still reference it. The other engagement
# serializers are imported directly from dojo.engagement.api by their consumers.
from dojo.engagement.api.serializer import EngagementSerializer  # noqa: E402 -- backward compat

# Product serializers live in dojo/product/api/serializer.py. ProductSerializer is
# re-exported because ReportGenerateSerializer (below) still references it;
# ProductMetaSerializer because dojo/asset/api/serializers.py imports it.
# ProductAPIScanConfigurationSerializer is imported directly from
# dojo.product.api.serializer by its only consumer (the viewset).
from dojo.product.api.serializer import (  # noqa: E402 -- backward compat
    ProductMetaSerializer,  # noqa: F401 -- backward compat
    ProductSerializer,
)
from dojo.product_type.api.serializer import ProductTypeSerializer  # noqa: E402


class RiskAcceptanceToNotesSerializer(serializers.Serializer):
    risk_acceptance_id = serializers.PrimaryKeyRelatedField(
        queryset=Risk_Acceptance.objects.all(), many=False, allow_null=True,
    )
    notes = NoteSerializer(many=True)


class AppAnalysisSerializer(serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)

    class Meta:
        model = App_Analysis
        fields = "__all__"


class ToolTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tool_Type
        fields = "__all__"

    def validate(self, data):
        if self.context["request"].method == "POST":
            name = data.get("name")
            # Make sure this will not create a duplicate test type
            if Tool_Type.objects.filter(name=name).count() > 0:
                msg = "A Tool Type with the name already exists"
                raise serializers.ValidationError(msg)
        return data


class RegulationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Regulation
        fields = "__all__"


class ToolConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tool_Configuration
        fields = "__all__"
        extra_kwargs = {
            "password": {"write_only": True},
            "ssh": {"write_only": True},
            "api_key": {"write_only": True},
        }


class ToolProductSettingsSerializer(serializers.ModelSerializer):
    setting_url = serializers.CharField(source="url")
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(), required=True,
    )

    class Meta:
        model = Tool_Product_Settings
        fields = "__all__"


class EndpointStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Endpoint_Status
        fields = "__all__"

    def run_validators(self, initial_data):
        try:
            return super().run_validators(initial_data)
        except RestFrameworkValidationError as exc:
            if "finding, endpoint must make a unique set" in str(exc):
                msg = "This endpoint-finding relation already exists"
                raise serializers.ValidationError(msg) from exc
            raise

    def create(self, validated_data):
        endpoint = validated_data.get("endpoint")
        finding = validated_data.get("finding")
        try:
            status = Endpoint_Status.objects.create(
                finding=finding, endpoint=endpoint,
            )
        except IntegrityError as ie:
            if "finding, endpoint must make a unique set" in str(ie):
                msg = "This endpoint-finding relation already exists"
                raise serializers.ValidationError(msg)
            raise
        status.mitigated = validated_data.get("mitigated", False)
        status.false_positive = validated_data.get("false_positive", False)
        status.out_of_scope = validated_data.get("out_of_scope", False)
        status.risk_accepted = validated_data.get("risk_accepted", False)
        status.date = validated_data.get("date", get_current_date())
        status.save()
        return status

    def update(self, instance, validated_data):
        try:
            return super().update(instance, validated_data)
        except IntegrityError as ie:
            if "finding, endpoint must make a unique set" in str(ie):
                msg = "This endpoint-finding relation already exists"
                raise serializers.ValidationError(msg)
            raise


class EndpointSerializer(serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)
    active_finding_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Endpoint
        exclude = ("inherited_tags",)

    def validate(self, data):

        if self.context["request"].method != "PATCH":
            if "product" not in data:
                msg = "Product is required"
                raise serializers.ValidationError(msg)
            protocol = data.get("protocol")
            userinfo = data.get("userinfo")
            host = data.get("host")
            port = data.get("port")
            path = data.get("path")
            query = data.get("query")
            fragment = data.get("fragment")
            product = data.get("product")
        else:
            protocol = data.get("protocol", self.instance.protocol)
            userinfo = data.get("userinfo", self.instance.userinfo)
            host = data.get("host", self.instance.host)
            port = data.get("port", self.instance.port)
            path = data.get("path", self.instance.path)
            query = data.get("query", self.instance.query)
            fragment = data.get("fragment", self.instance.fragment)
            if "product" in data and data["product"] != self.instance.product:
                msg = "Change of product is not possible"
                raise serializers.ValidationError(msg)
            product = self.instance.product

        endpoint_ins = Endpoint(
            protocol=protocol,
            userinfo=userinfo,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            product=product,
        )
        endpoint_ins.clean()  # Run standard validation and clean process; can raise errors

        endpoint = endpoint_filter(
            protocol=endpoint_ins.protocol,
            userinfo=endpoint_ins.userinfo,
            host=endpoint_ins.host,
            port=endpoint_ins.port,
            path=endpoint_ins.path,
            query=endpoint_ins.query,
            fragment=endpoint_ins.fragment,
            product=endpoint_ins.product,
        )
        if (
            self.context["request"].method in {"PUT", "PATCH"}
            and (
                (endpoint.count() > 1)
                or (
                    endpoint.count() == 1
                    and endpoint.first().pk != self.instance.pk
                )
            )
        ) or (
            self.context["request"].method == "POST" and endpoint.count() > 0
        ):
            msg = (
                "It appears as though an endpoint with this data already "
                "exists for this product."
            )
            raise serializers.ValidationError(msg, code="invalid")

        # use clean data
        data["protocol"] = endpoint_ins.protocol
        data["userinfo"] = endpoint_ins.userinfo
        data["host"] = endpoint_ins.host
        data["port"] = endpoint_ins.port
        data["path"] = endpoint_ins.path
        data["query"] = endpoint_ins.query
        data["fragment"] = endpoint_ins.fragment
        data["product"] = endpoint_ins.product

        return data


class EndpointParamsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Endpoint_Params
        fields = "__all__"


from dojo.jira.api.serializers import (  # noqa: E402, F401 backward compat
    JIRAInstanceSerializer,
    JIRAIssueSerializer,
    JIRAProjectSerializer,
)


class SonarqubeIssueSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sonarqube_Issue
        fields = "__all__"


class SonarqubeIssueTransitionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sonarqube_Issue_Transition
        fields = "__all__"


class DevelopmentEnvironmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Development_Environment
        fields = "__all__"


from dojo.test.api.serializer import TestSerializer  # noqa: E402 -- backward compat re-export


class RiskAcceptanceSerializer(serializers.ModelSerializer):
    path = serializers.SerializerMethodField()

    def create(self, validated_data):
        instance = super().create(validated_data)
        user = getattr(self.context.get("request", None), "user", None)
        ra_helper.add_findings_to_risk_acceptance(user, instance, instance.accepted_findings.all())

        # Add risk acceptance to engagement
        # This is fine as Pro has its own model + relationshop to track links with engagements.
        if instance.accepted_findings.exists():
            engagement = instance.accepted_findings.first().test.engagement
            engagement.risk_acceptance.add(instance)

        return instance

    def update(self, instance, validated_data):
        # Determine findings to risk accept, and findings to unaccept risk
        existing_findings = Finding.objects.filter(risk_acceptance=self.instance.id)
        new_findings_ids = [x.id for x in validated_data.get("accepted_findings", [])]
        new_findings = Finding.objects.filter(id__in=new_findings_ids)
        findings_to_add = set(new_findings) - set(existing_findings)
        findings_to_remove = set(existing_findings) - set(new_findings)
        findings_to_add = Finding.objects.filter(id__in=[x.id for x in findings_to_add])
        findings_to_remove = Finding.objects.filter(id__in=[x.id for x in findings_to_remove])
        # Make the update in the database
        instance = super().update(instance, validated_data)
        user = getattr(self.context.get("request", None), "user", None)
        # Add the new findings
        ra_helper.add_findings_to_risk_acceptance(user, instance, findings_to_add)
        # Remove the ones that were not present in the payload
        for finding in findings_to_remove:
            ra_helper.remove_finding_from_risk_acceptance(user, instance, finding)

        # Handle orphaned risk acceptances: link to engagement if it now has findings
        # This is fine as Pro has its own model + relationshop to track links with engagements.
        if instance.accepted_findings.exists() and not instance.engagement:
            engagement = instance.accepted_findings.first().test.engagement
            engagement.risk_acceptance.add(instance)

        return instance

    @extend_schema_field(serializers.CharField())
    def get_path(self, obj):
        engagement = Engagement.objects.filter(
            risk_acceptance__id__in=[obj.id],
        ).first()
        path = "No proof has been supplied"
        if engagement and obj.filename() is not None:
            path = reverse(
                "download_risk_acceptance", args=(engagement.id, obj.id),
            )
            request = self.context.get("request")
            if request:
                path = request.build_absolute_uri(path)
        return path

    @extend_schema_field(serializers.IntegerField())
    def get_engagement(self, obj):
        engagement = Engagement.objects.filter(
            risk_acceptance__id__in=[obj.id],
        ).first()
        return EngagementSerializer(read_only=True).to_representation(
            engagement,
        )

    def validate(self, data):
        def validate_findings_have_same_engagement(finding_objects: list[Finding]):
            engagements = finding_objects.values_list("test__engagement__id", flat=True).distinct().count()
            if engagements > 1:
                msg = "You are not permitted to add findings from multiple engagements"
                raise PermissionDenied(msg)

        findings = data.get("accepted_findings", [])
        findings_ids = [x.id for x in findings]
        finding_objects = Finding.objects.filter(id__in=findings_ids)
        authed_findings = get_authorized_findings("edit").filter(id__in=findings_ids)
        if len(findings) != len(authed_findings):
            msg = "You are not permitted to add one or more selected findings to this risk acceptance"
            raise PermissionDenied(msg)
        if self.context["request"].method == "POST":
            validate_findings_have_same_engagement(finding_objects)

            # Validate product allows full risk acceptance BEFORE creating instance
            if finding_objects.exists():
                engagement = finding_objects.first().test.engagement
                if not engagement.product.enable_full_risk_acceptance:
                    msg = "Full risk acceptance is not enabled for this product"
                    raise PermissionDenied(msg)
        elif self.context["request"].method in {"PATCH", "PUT"}:
            # Use the reverse relation instead of filtering
            existing_findings = self.instance.accepted_findings.all()
            existing_and_new_findings = existing_findings | finding_objects
            validate_findings_have_same_engagement(existing_and_new_findings)

            # Explicit check to prevent engagement switching
            risk_acceptance_engagement = self.instance.engagement
            if risk_acceptance_engagement and finding_objects.exists():
                new_findings_engagement = finding_objects.first().test.engagement
                if risk_acceptance_engagement.id != new_findings_engagement.id:
                    msg = f"Risk Acceptance belongs to engagement {risk_acceptance_engagement.id}. Cannot add findings from engagement {new_findings_engagement.id}"
                    raise ValidationError(msg)
        return data

    class Meta:
        model = Risk_Acceptance
        fields = "__all__"


class CommonImportScanSerializer(serializers.Serializer):
    scan_date = serializers.DateField(
        required=False,
        help_text="Scan completion date will be used on all findings.",
    )

    minimum_severity = serializers.ChoiceField(
        choices=SEVERITY_CHOICES,
        default="Info",
        help_text="Minimum severity level to be imported",
    )
    active = serializers.BooleanField(
        help_text="Force findings to be active/inactive or default to the original tool (None)", required=False,
    )
    verified = serializers.BooleanField(
        help_text="Force findings to be verified/not verified or default to the original tool (None)", required=False,
    )
    endpoint_to_add = serializers.PrimaryKeyRelatedField(
        queryset=Location.objects.all(),
        required=False,
        default=None,
        help_text="Enter the ID of a Location that is associated with the target Product. New Findings will be added to that Location.",
    )
    file = serializers.FileField(
        allow_empty_file=True,
        required=False,
        validators=[ImporterFileExtensionValidator()],
    )
    product_type_name = serializers.CharField(
        required=False,
        help_text=_("Also referred to as 'Organization' name."),
    )
    product_name = serializers.CharField(
        required=False,
        help_text=_("Also referred to as 'Asset' name."),
    )
    engagement_name = serializers.CharField(required=False)
    engagement_end_date = serializers.DateField(
        required=False,
        help_text="End Date for Engagement. Default is current time + 365 days. Required format year-month-day",
    )
    source_code_management_uri = serializers.URLField(
        max_length=600,
        required=False,
        help_text="Resource link to source code",
    )

    test_title = serializers.CharField(required=False)
    auto_create_context = serializers.BooleanField(required=False)
    deduplication_on_engagement = serializers.BooleanField(required=False)
    lead = serializers.PrimaryKeyRelatedField(
        allow_null=True, default=None, queryset=User.objects.all(),
    )
    push_to_jira = serializers.BooleanField(default=False)
    environment = serializers.CharField(required=False)
    build_id = serializers.CharField(
        required=False, help_text="ID of the build that was scanned.",
    )
    branch_tag = serializers.CharField(
        required=False, help_text="Branch or Tag that was scanned.",
    )
    commit_hash = serializers.CharField(
        required=False, help_text="Commit that was scanned.",
    )
    api_scan_configuration = serializers.PrimaryKeyRelatedField(
        allow_null=True,
        default=None,
        queryset=Product_API_Scan_Configuration.objects.all(),
    )
    service = serializers.CharField(
        required=False,
        help_text="A service is a self-contained piece of functionality within a Product. "
        "This is an optional field which is used in deduplication and closing of old findings when set. "
        "This affects the whole engagement/product depending on your deduplication scope.",
    )
    group_by = serializers.ChoiceField(
        required=False,
        choices=Finding_Group.GROUP_BY_OPTIONS,
        help_text="Choose an option to automatically group new findings by the chosen option.",
    )
    create_finding_groups_for_all_findings = serializers.BooleanField(
        help_text="If set to false, finding groups will only be created when there is more than one grouped finding",
        required=False,
        default=True,
    )
    # extra fields populated in response
    # need to use the _id suffix as without the serializer framework gets
    # confused
    test_id = serializers.IntegerField(read_only=True)
    engagement_id = serializers.IntegerField(read_only=True)
    product_id = serializers.IntegerField(
        read_only=True,
        help_text=_("Also referred to as 'Asset' ID."),
    )
    product_type_id = serializers.IntegerField(
        read_only=True,
        help_text=_("Also referred to as 'Organization' ID."),
    )
    statistics = ImportStatisticsSerializer(read_only=True, required=False)
    pro = serializers.ListField(read_only=True, required=False)
    apply_tags_to_findings = serializers.BooleanField(
        help_text="If set to True, the tags will be applied to the findings",
        required=False,
    )
    apply_tags_to_endpoints = serializers.BooleanField(
        help_text="If set to True, the tags will be applied to the locations",
        required=False,
    )

    # TODO: Delete this after the move to Locations
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not settings.V3_FEATURE_LOCATIONS:
            # TODO: why do we allow only existing endpoints?
            self.fields["endpoint_to_add"] = serializers.PrimaryKeyRelatedField(
                queryset=Endpoint.objects.all(),
                required=False,
                default=None,
                help_text="Enter the ID of an Endpoint that is associated with the target Product. New Findings will be added to that Endpoint.",
            )

    def get_importer(
        self,
        **kwargs: dict,
    ) -> BaseImporter:
        """
        Returns a new instance of an importer that extends
        the BaseImporter class
        """
        return DefaultImporter(**kwargs)

    def process_scan(
        self,
        data: dict,
        context: dict,
    ) -> None:
        """
        Process the scan with all of the supplied data fully massaged
        into the format we are expecting

        Raises exceptions in the event of an error
        """
        try:
            logger.debug(f"process_scan called with context: {context}")
            start_time = time.perf_counter()
            importer = self.get_importer(**context)
            context["test"], _, _, _, _, _, _ = importer.process_scan(
                context.pop("scan", None),
            )
            # Update the response body with some new data
            if test := context.get("test"):
                data["test"] = test.id
                data["test_id"] = test.id
                data["engagement_id"] = test.engagement.id
                data["product_id"] = test.engagement.product.id
                data["product_type_id"] = test.engagement.product.prod_type.id
                data["statistics"] = {"after": test.statistics}
            duration = time.perf_counter() - start_time
            LargeScanSizeProductAnnouncement(response_data=data, duration=duration)
            ScanTypeProductAnnouncement(response_data=data, scan_type=context.get("scan_type"))
        # convert to exception otherwise django rest framework will swallow them as 400 error
        # exceptions are already logged in the importer
        except SyntaxError as se:
            raise Exception(se)
        except ValueError as ve:
            raise Exception(ve)

    def validate(self, data: dict) -> dict:
        scan_type = data.get("scan_type")
        file = data.get("file")
        if not file and requires_file(scan_type):
            msg = f"Uploading a Report File is required for {scan_type}"
            raise serializers.ValidationError(msg)
        if file and is_scan_file_too_large(file):
            msg = f"Report file is too large. Maximum supported size is {settings.SCAN_FILE_MAX_SIZE} MB"
            raise serializers.ValidationError(msg)
        tool_type = requires_tool_type(scan_type)
        if tool_type:
            api_scan_configuration = data.get("api_scan_configuration")
            if (
                api_scan_configuration
                and tool_type
                != api_scan_configuration.tool_configuration.tool_type.name
            ):
                msg = f"API scan configuration must be of tool type {tool_type}"
                raise serializers.ValidationError(msg)
        return data

    def validate_scan_date(self, value: str) -> None:
        if value and value > timezone.localdate():
            msg = "The scan_date cannot be in the future!"
            raise serializers.ValidationError(msg)
        return value

    def setup_common_context(self, data: dict) -> dict:
        """
        Process all of the user supplied inputs to massage them into the correct
        format the importer is expecting to see
        """
        context = dict(data)
        # update some vars
        context["scan"] = data.pop("file", None)

        if context.get("auto_create_context"):
            environment = Development_Environment.objects.get_or_create(name=data.get("environment", "Development"))[0]
        else:
            try:
                environment = Development_Environment.objects.get(name=data.get("environment", "Development"))
            except:
                msg = "Environment named " + data.get("environment") + " does not exist."
                raise ValidationError(msg)

        context["environment"] = environment
        # Set the active/verified status based upon the overrides
        if "active" in self.initial_data:
            context["active"] = data.get("active")
        else:
            context["active"] = None
        if "verified" in self.initial_data:
            context["verified"] = data.get("verified")
        else:
            context["verified"] = None
        if endpoints_to_add := data.get("endpoint_to_add"):
            if settings.V3_FEATURE_LOCATIONS:
                # Note: The serializer resolves Location references, but we must pass along to the importer
                # AbstractLocation objects, hence the .url access.
                context["endpoints_to_add"] = [endpoints_to_add.url]
            else:
                # TODO: Delete this after the move to Locations
                context["endpoints_to_add"] = [endpoints_to_add]
        else:
            context["endpoints_to_add"] = None
        # Convert the tags to a list if needed. At this point, the
        # TaggitListSerializer has already removed commas supplied
        # by the user, so this operation will consistently return
        # a list to be used by the importer
        if tags := context.get("tags"):
            if isinstance(tags, str):
                context["tags"] = tags.split(", ")
        # have to make the scan_date_time timezone aware otherwise uploads via
        # the API would fail (but unit tests for api upload would pass...)
        context["scan_date"] = (
            timezone.make_aware(
                datetime.combine(context.get("scan_date"), datetime.min.time()),
            )
            if context.get("scan_date")
            else None
        )

        # engagement end date was not being used at all and so target_end would also turn into None
        # in this case, do not want to change target_end unless engagement_end exists
        eng_end_date = context.get("engagement_end_date")
        if eng_end_date:
            context["target_end"] = context.get("engagement_end_date")

        return context


class ImportScanSerializer(CommonImportScanSerializer):
    scan_type = serializers.ChoiceField(choices=get_choices_sorted())
    engagement = serializers.PrimaryKeyRelatedField(
        queryset=Engagement.objects.all(), required=False,
    )
    tags = TagListSerializerField(
        required=False, allow_empty=True, help_text="Add tags that help describe this scan.",
    )
    close_old_findings = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Old findings no longer present in the new report get closed as mitigated when importing. "
                    "If service has been set, only the findings for this service will be closed; "
                    "if no service is set, only findings without a service will be closed. "
                    "This only affects findings within the same engagement.",
    )
    close_old_findings_product_scope = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Old findings no longer present in the new report get closed as mitigated when importing. "
                    "If service has been set, only the findings for this service will be closed; "
                    "if no service is set, only findings without a service will be closed. "
                    "This only affects findings within the same product."
                    "By default, it is false meaning that only old findings of the same type in the engagement are in scope.",
    )
    version = serializers.CharField(
        required=False, help_text="Version that was scanned.",
    )
    # extra fields populated in response
    # need to use the _id suffix as without the serializer framework gets
    # confused
    test = serializers.IntegerField(
        read_only=True,
    )  # left for backwards compatibility

    def set_context(
        self,
        data: dict,
    ) -> dict:
        context = self.setup_common_context(data)
        # Process the auto create context inputs
        self.process_auto_create_create_context(context)

        return context

    def process_auto_create_create_context(
        self,
        context: dict,
    ) -> None:
        """
        Extract all of the pertinent args used to auto create any product
        types, products, or engagements. This function will also validate
        those inputs for any required info that is not present. In the event
        of an error, an exception will be raised and bubble up to the user
        """
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            auto_create.process_import_meta_data_from_dict(context)
            # Attempt to create an engagement
            context["engagement"] = auto_create.get_or_create_engagement(**context)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(str(e))

    def save(self, *, push_to_jira=False):
        # Go through the validate method
        data = self.validated_data
        # Extract the data from the form
        context = self.set_context(data)
        # set the jira option again as it was overridden
        context["push_to_jira"] = push_to_jira
        # Import the scan with all of the supplied data
        self.process_scan(data, context)


class ReImportScanSerializer(CommonImportScanSerializer):

    help_do_not_reactivate = "Select if the import should ignore active findings from the report, useful for triage-less scanners. Will keep existing findings closed, without reactivating them. For more information check the docs."
    do_not_reactivate = serializers.BooleanField(
        default=False, required=False, help_text=help_do_not_reactivate,
    )
    scan_type = serializers.ChoiceField(
        choices=get_choices_sorted(), required=True,
    )
    test = serializers.PrimaryKeyRelatedField(
        required=False, queryset=Test.objects.all(),
    )
    # Close the old findings if the parameter is not provided. This is to
    # maintain the old API behavior after reintroducing the close_old_findings parameter
    # also for ReImport.
    close_old_findings = serializers.BooleanField(
        required=False,
        default=True,
        help_text="Old findings no longer present in the new report get closed as mitigated when importing. "
                    "If service has been set, only the findings for this service will be closed; "
                    "if no service is set, only findings without a service will be closed. "
                    "This only affects findings within the same test.",
    )
    close_old_findings_product_scope = serializers.BooleanField(
        required=False,
        default=False,
        help_text="This has no effect on reimport",
    )
    version = serializers.CharField(
        required=False,
        help_text="Version that will be set on existing Test object. Leave empty to leave existing value in place.",
    )
    tags = TagListSerializerField(
        required=False,
        allow_empty=True,
        help_text="Modify existing tags that help describe this scan. (Existing test tags will be overwritten)",
    )

    def set_context(
        self,
        data: dict,
    ) -> dict:

        return self.setup_common_context(data)

    def process_auto_create_create_context(
        self,
        auto_create_manager: AutoCreateContextManager,
        context: dict,
    ) -> None:
        """
        Extract all of the pertinent args used to auto create any product
        types, products, or engagements. This function will also validate
        those inputs for any required info that is not present. In the event
        of an error, an exception will be raised and bubble up to the user
        """
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            auto_create_manager.process_import_meta_data_from_dict(context)
            context["product"] = auto_create_manager.get_target_product_if_exists(**context)
            context["engagement"] = auto_create_manager.get_target_engagement_if_exists(**context)
            context["test"] = auto_create_manager.get_target_test_if_exists(**context)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(str(e))

    def get_reimporter(
        self,
        **kwargs: dict,
    ) -> BaseImporter:
        """
        Returns a new instance of a reimporter that extends
        the BaseImporter class
        """
        return DefaultReImporter(**kwargs)

    def process_scan(
        self,
        auto_create_manager: AutoCreateContextManager,
        data: dict,
        context: dict,
    ) -> None:
        """
        Process the scan with all of the supplied data fully massaged
        into the format we are expecting

        Raises exceptions in the event of an error
        """
        statistics_before, statistics_delta = None, None
        try:
            logger.debug(f"process_scan called with context: {context}")
            start_time = time.perf_counter()
            if test := context.get("test"):
                statistics_before = test.statistics
                context["test"], _, _, _, _, _, test_import = self.get_reimporter(
                    **context,
                ).process_scan(
                    context.pop("scan", None),
                )
                if test_import:
                    statistics_delta = test_import.statistics
            elif context.get("auto_create_context"):
                # Attempt to create an engagement
                logger.debug("reimport for non-existing test, using import to create new test")
                context["engagement"] = auto_create_manager.get_or_create_engagement(**context)
                # Do not close old findings when creating a brand new test: there are no
                # existing findings to compare against, and close_old_findings would
                # incorrectly close findings from other tests in the same scope.
                context["test"], _, _, _, _, _, _ = self.get_importer(
                    **{**context, "close_old_findings": False},
                ).process_scan(
                    context.pop("scan", None),
                )
            else:
                msg = "A test could not be found!"
                raise NotFound(msg)
            # Update the response body with some new data
            if test := context.get("test"):
                data["test"] = test
                data["test_id"] = test.id
                data["engagement_id"] = test.engagement.id
                data["product_id"] = test.engagement.product.id
                data["product_type_id"] = test.engagement.product.prod_type.id
                data["statistics"] = {}
                if statistics_before:
                    data["statistics"]["before"] = statistics_before
                if statistics_delta:
                    data["statistics"]["delta"] = statistics_delta
                data["statistics"]["after"] = test.statistics
            duration = time.perf_counter() - start_time
            LargeScanSizeProductAnnouncement(response_data=data, duration=duration)
            ScanTypeProductAnnouncement(response_data=data, scan_type=context.get("scan_type"))
        # convert to exception otherwise django rest framework will swallow them as 400 error
        # exceptions are already logged in the importer
        except SyntaxError as se:
            raise Exception(se)
        except ValueError as ve:
            raise Exception(ve)

    def save(self, *, push_to_jira=False):
        # Go through the validate method
        data = self.validated_data
        # Extract the data from the form
        context = self.set_context(data)
        # set the jira option again as it was overridden
        context["push_to_jira"] = push_to_jira
        # Process the auto create context inputs
        auto_create_manager = AutoCreateContextManager()
        self.process_auto_create_create_context(auto_create_manager, context)
        # Import the scan with all of the supplied data
        self.process_scan(auto_create_manager, data, context)


class EndpointMetaImporterSerializer(serializers.Serializer):
    file = serializers.FileField(required=True)
    create_endpoints = serializers.BooleanField(default=True, required=False)
    create_tags = serializers.BooleanField(default=True, required=False)
    create_dojo_meta = serializers.BooleanField(default=False, required=False)
    product_name = serializers.CharField(required=False)
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(), required=False,
    )
    # extra fields populated in response
    # need to use the _id suffix as without the serializer framework gets
    # confused
    product_id = serializers.IntegerField(read_only=True)

    def validate(self, data):
        file = data.get("file")
        if file and is_scan_file_too_large(file):
            msg = f"Report file is too large. Maximum supported size is {settings.SCAN_FILE_MAX_SIZE} MB"
            raise serializers.ValidationError(msg)

        return data

    def save(self):
        data = self.validated_data
        file = data.get("file")
        create_endpoints = data.get("create_endpoints", True)
        create_tags = data.get("create_tags", True)
        create_dojo_meta = data.get("create_dojo_meta", False)
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            auto_create.process_import_meta_data_from_dict(data)
            # Get an existing product
            product = auto_create.get_target_product_if_exists(**data)
            if not product:
                product = auto_create.get_target_product_by_id_if_exists(**data)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(str(e))
        try:
            if settings.V3_FEATURE_LOCATIONS:
                endpoint_meta_import(
                    file,
                    product,
                    create_endpoints,
                    create_tags,
                    create_dojo_meta,
                    origin="API",
                    object_class=Location,
                )
            else:
                # TODO: Delete this after the move to Locations
                endpoint_meta_import(
                    file,
                    product,
                    create_endpoints,
                    create_tags,
                    create_dojo_meta,
                    origin="API",
                )
        except SyntaxError as se:
            raise Exception(se)
        except ValueError as ve:
            raise Exception(ve)


class LanguageTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Language_Type
        fields = "__all__"


class LanguageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Languages
        fields = "__all__"


class ImportLanguagesSerializer(serializers.Serializer):
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(), required=True,
    )
    file = serializers.FileField(required=True)

    def save(self):
        data = self.validated_data
        product = data["product"]
        languages = data["file"]

        try:
            data = languages.read()
            try:
                deserialized = json.loads(str(data, "utf-8"))
            except Exception:
                deserialized = json.loads(data)
        except Exception:
            msg = "Invalid format"
            raise serializers.ValidationError(msg)

        # Filter out ignored keys and deduplicate
        language_names = list(dict.fromkeys(
            name for name in deserialized if name not in {"header", "SUM"}
        ))
        # Ensure any new Language_Type records exist (ignore conflicts from
        # concurrent requests or already-existing types)
        Language_Type.objects.bulk_create(
            [Language_Type(language=name) for name in language_names],
            ignore_conflicts=True,
        )
        # Single query to fetch all Language_Type objects we need (indexed lookup)
        language_types = {
            lt.language: lt
            for lt in Language_Type.objects.filter(language__in=language_names)
        }
        # Prepare Languages objects for upsert
        languages_to_upsert = [
            Languages(
                product=product,
                language=language_types[name],
                files=deserialized[name].get("nFiles", 0),
                blank=deserialized[name].get("blank", 0),
                comment=deserialized[name].get("comment", 0),
                code=deserialized[name].get("code", 0),
            )
            for name in language_names
        ]
        # Upsert Languages and remove stale ones atomically
        try:
            with transaction.atomic():
                Languages.objects.bulk_create(
                    languages_to_upsert,
                    update_conflicts=True,
                    unique_fields=["language", "product"],
                    update_fields=["files", "blank", "comment", "code"],
                )
                # Remove languages no longer present in the file
                Languages.objects.filter(product=product).exclude(
                    language__in=language_types.values(),
                ).delete()
        except IntegrityError as e:
            msg = f"Failed to import languages due to a data integrity issue: {e}"
            raise serializers.ValidationError(msg)

    def validate(self, data):
        if is_scan_file_too_large(data["file"]):
            msg = f"File is too large. Maximum supported size is {settings.SCAN_FILE_MAX_SIZE} MB"
            raise serializers.ValidationError(msg)
        return data


class AddNewNoteOptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notes
        fields = ["entry", "private", "note_type"]


class AddNewFileOptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileUpload
        fields = "__all__"


class ReportGenerateOptionSerializer(serializers.Serializer):
    include_finding_notes = serializers.BooleanField(default=False)
    include_finding_images = serializers.BooleanField(default=False)
    include_executive_summary = serializers.BooleanField(default=False)
    include_table_of_contents = serializers.BooleanField(default=False)


class ExecutiveSummarySerializer(serializers.Serializer):
    engagement_name = serializers.CharField(max_length=200)
    engagement_target_start = serializers.DateField()
    engagement_target_end = serializers.DateField()
    test_type_name = serializers.CharField(max_length=200)
    test_target_start = serializers.DateTimeField()
    test_target_end = serializers.DateTimeField()
    test_environment_name = serializers.CharField(max_length=200)
    test_strategy_ref = serializers.URLField(
        max_length=200, min_length=None, allow_blank=True,
    )
    total_findings = serializers.IntegerField()


# Finding serializers live in dojo/finding/api/serializer.py. FindingSerializer and
# FindingToNotesSerializer are re-exported here because ReportGenerateSerializer
# (below) still references them. The remaining finding serializers are re-exported so
# they remain discoverable as members of this module by the prefetcher
# (dojo/api_v2/prefetch/prefetcher.py inspects this module to build its model->serializer
# map); changing that membership would silently change prefetch responses.
from dojo.finding.api.serializer import (  # noqa: E402 -- backward compat
    BurpRawRequestResponseMultiSerializer,  # noqa: F401 -- backward compat / prefetcher discovery
    BurpRawRequestResponseSerializer,  # noqa: F401 -- backward compat
    FindingCloseSerializer,  # noqa: F401 -- backward compat / prefetcher discovery
    FindingCreateSerializer,  # noqa: F401 -- backward compat / prefetcher discovery
    FindingEngagementSerializer,  # noqa: F401 -- backward compat / prefetcher discovery
    FindingEnvironmentSerializer,  # noqa: F401 -- backward compat / prefetcher discovery
    FindingGroupSerializer,  # noqa: F401 -- backward compat / prefetcher discovery
    FindingMetaSerializer,  # noqa: F401 -- backward compat / prefetcher discovery
    FindingProdTypeSerializer,  # noqa: F401 -- backward compat / prefetcher discovery
    FindingProductSerializer,  # noqa: F401 -- backward compat / prefetcher discovery
    FindingSerializer,
    FindingTemplateSerializer,  # noqa: F401 -- backward compat / prefetcher discovery
    FindingTestTypeSerializer,  # noqa: F401 -- backward compat / prefetcher discovery
    FindingToNotesSerializer,
    VulnerabilityIdSerializer,  # noqa: F401 -- backward compat / prefetcher discovery
)


class ReportGenerateSerializer(serializers.Serializer):
    executive_summary = ExecutiveSummarySerializer(many=False, allow_null=True)
    product_type = ProductTypeSerializer(many=False, read_only=True)
    product = ProductSerializer(many=False, read_only=True)
    engagement = EngagementSerializer(many=False, read_only=True)
    report_name = serializers.CharField(max_length=200)
    report_info = serializers.CharField(max_length=200)
    test = TestSerializer(many=False, read_only=True)
    endpoint = EndpointSerializer(many=False, read_only=True)
    endpoints = EndpointSerializer(many=True, read_only=True)
    findings = FindingSerializer(many=True, read_only=True)
    user = UserStubSerializer(many=False, read_only=True)
    team_name = serializers.CharField(max_length=200)
    title = serializers.CharField(max_length=200)
    user_id = serializers.IntegerField()
    host = serializers.CharField(max_length=200)
    finding_notes = FindingToNotesSerializer(
        many=True, allow_null=True, required=False,
    )


from dojo.jira.api.serializers import (  # noqa: E402, F401 backward compat
    EngagementUpdateJiraEpicSerializer,
)


class TagSerializer(serializers.Serializer):
    tags = TagListSerializerField(required=True)


from dojo.system_settings.api.serializer import SystemSettingsSerializer  # noqa: E402, F401 -- backward compat


class CeleryStatusSerializer(serializers.Serializer):
    worker_status = serializers.BooleanField(read_only=True)
    broker_status = serializers.BooleanField(read_only=True)
    queue_length = serializers.IntegerField(allow_null=True, read_only=True)
    task_time_limit = serializers.IntegerField(allow_null=True, read_only=True)
    task_soft_time_limit = serializers.IntegerField(allow_null=True, read_only=True)
    task_default_expires = serializers.IntegerField(allow_null=True, read_only=True)


class CeleryQueueTaskDetailSerializer(serializers.Serializer):
    task_name = serializers.CharField(read_only=True)
    count = serializers.IntegerField(read_only=True)
    oldest_position = serializers.IntegerField(read_only=True)
    newest_position = serializers.IntegerField(read_only=True)
    oldest_eta = serializers.CharField(allow_null=True, read_only=True)
    newest_eta = serializers.CharField(allow_null=True, read_only=True)
    earliest_expires = serializers.CharField(allow_null=True, read_only=True)
    latest_expires = serializers.CharField(allow_null=True, read_only=True)


from dojo.notifications.api.serializer import NotificationsSerializer  # noqa: E402, F401  -- backward compat


class NetworkLocationsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Network_Locations
        fields = "__all__"


class SLAConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = SLA_Configuration
        exclude = (
            "async_updating",
        )

    def validate(self, data):
        async_updating = getattr(self.instance, "async_updating", None)
        if async_updating:
            for field in ["critical", "enforce_critical", "high", "enforce_high", "medium", "enforce_medium", "low", "enforce_low"]:
                old_days = getattr(self.instance, field, None)
                new_days = data.get(field, None)
                if old_days is not None and new_days is not None and (old_days != new_days):
                    msg = "Finding SLA expiration dates are currently being calculated. The SLA days for this SLA configuration cannot be changed until the calculation is complete."
                    raise serializers.ValidationError(msg)
        return data


class DeletePreviewSerializer(serializers.Serializer):
    model = serializers.CharField(read_only=True)
    id = serializers.IntegerField(read_only=True, allow_null=True)
    name = serializers.CharField(read_only=True)


class ConfigurationPermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        exclude = ("content_type",)


class AnnouncementSerializer(serializers.ModelSerializer):

    class Meta:
        model = Announcement
        fields = "__all__"

    def create(self, validated_data):
        validated_data["id"] = 1
        try:
            return super().create(validated_data)
        except IntegrityError as e:
            if 'duplicate key value violates unique constraint "dojo_announcement_pkey"' in str(e):
                msg = "No more than one Announcement is allowed"
                raise serializers.ValidationError(msg)
            raise


from dojo.notifications.api.serializer import NotificationWebhooksSerializer  # noqa: E402, F401  -- backward compat
