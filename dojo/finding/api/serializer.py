import base64
import collections
import json
import logging

import six
from django.conf import settings
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers
from rest_framework.fields import DictField

import dojo.finding.helper as finding_helper
from dojo.authorization.authorization import user_has_permission
from dojo.celery_dispatch import dojo_dispatch_task
from dojo.finding.helper import (
    save_cwes,
    save_endpoints_template,
    save_vulnerability_ids,
    save_vulnerability_ids_template,
)
from dojo.finding.models import BurpRawRequestResponse
from dojo.finding.vulnerability_id import cwe_label, cwe_number
from dojo.jira import services as jira_services
from dojo.jira.api.serializers import JIRAIssueSerializer
from dojo.location.models import LocationFindingReference
from dojo.models import (
    SEVERITIES,
    Development_Environment,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Engagement,
    Finding,
    Finding_CWE,
    Finding_Group,
    Finding_Template,
    Note_Type,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
    Vulnerability_Id,
)
from dojo.notifications.helper import async_create_notification
from dojo.user.queries import get_authorized_users

logger = logging.getLogger(__name__)


class RequestResponseDict(collections.UserList):
    def __init__(self, *args, **kwargs):
        pretty_print = kwargs.pop("pretty_print", True)
        collections.UserList.__init__(self, *args, **kwargs)
        self.pretty_print = pretty_print

    def __add__(self, rhs):
        return RequestResponseDict(list.__add__(self, rhs))

    def __getitem__(self, item):
        result = list.__getitem__(self, item)
        try:
            return RequestResponseDict(result)
        except TypeError:
            return result

    def __str__(self):
        if self.pretty_print:
            return json.dumps(
                self, sort_keys=True, indent=4, separators=(",", ": "),
            )
        return json.dumps(self)


class RequestResponseSerializerField(serializers.ListSerializer):
    child = DictField(child=serializers.CharField())
    default_error_messages = {
        "not_a_list": _(
            'Expected a list of items but got type "{input_type}".',
        ),
        "invalid_json": _(
            "Invalid json list. A tag list submitted in string"
            " form must be valid json.",
        ),
        "not_a_dict": _(
            "All list items must be of dict type with keys 'request' and 'response'",
        ),
        "not_a_str": _("All values in the dict must be of string type."),
    }
    order_by = None

    def __init__(self, **kwargs):
        pretty_print = kwargs.pop("pretty_print", True)

        style = kwargs.pop("style", {})
        kwargs["style"] = {"base_template": "textarea.html"}
        kwargs["style"].update(style)

        if "data" in kwargs:
            data = kwargs["data"]

            if isinstance(data, list):
                kwargs["many"] = True

        super().__init__(**kwargs)

        self.pretty_print = pretty_print

    def to_internal_value(self, data):
        if isinstance(data, six.string_types):
            if not data:
                data = []
            try:
                data = json.loads(data)
            except ValueError:
                self.fail("invalid_json")

        if not isinstance(data, list):
            self.fail("not_a_list", input_type=type(data).__name__)
        for s in data:
            if not isinstance(s, dict):
                self.fail("not_a_dict", input_type=type(s).__name__)

            request = s.get("request", None)
            response = s.get("response", None)

            if not isinstance(request, str):
                self.fail("not_a_str", input_type=type(request).__name__)
            if not isinstance(response, str):
                self.fail("not_a_str", input_type=type(request).__name__)

            self.child.run_validation(s)
        return data

    def to_representation(self, value):
        if not isinstance(value, RequestResponseDict):
            if not isinstance(value, list):
                # this will trigger when a queryset is found...
                burps = value.all().order_by(*self.order_by) if self.order_by else value.all()
                value = [
                    {
                        "request": burp.get_request(),
                        "response": burp.get_response(),
                    }
                    for burp in burps
                ]

        return value


class BurpRawRequestResponseSerializer(serializers.Serializer):
    req_resp = RequestResponseSerializerField(required=True)


class BurpRawRequestResponseMultiSerializer(serializers.ModelSerializer):
    burpRequestBase64 = serializers.CharField()
    burpResponseBase64 = serializers.CharField()

    def to_representation(self, data):
        return {
            "id": data.id,
            "finding": data.finding.id,
            "burpRequestBase64": data.burpRequestBase64.decode("utf-8"),
            "burpResponseBase64": data.burpResponseBase64.decode("utf-8"),
        }

    def validate(self, data):
        b64request = data.get("burpRequestBase64", None)
        b64response = data.get("burpResponseBase64", None)
        finding = data.get("finding", None)
        # Make sure all fields are present
        if not b64request or not b64response or not finding:
            msg = "burpRequestBase64, burpResponseBase64, and finding are required."
            raise ValidationError(msg)
        # Verify we have true base64 decoding
        try:
            base64.b64decode(b64request, validate=True)
            base64.b64decode(b64response, validate=True)
        except Exception as e:
            msg = "Inputs need to be valid base64 encodings"
            raise ValidationError(msg) from e
        # Encode the data in utf-8 to remove any bad characters
        data["burpRequestBase64"] = b64request.encode("utf-8")
        data["burpResponseBase64"] = b64response.encode("utf-8")
        # Run the model validation - an ValidationError will be raised if there is an issue
        BurpRawRequestResponse(finding=finding, burpRequestBase64=b64request, burpResponseBase64=b64response).clean()

        return data

    class Meta:
        model = BurpRawRequestResponse
        fields = "__all__"


class FindingGroupSerializer(serializers.ModelSerializer):
    jira_issue = JIRAIssueSerializer(read_only=True, allow_null=True)

    class Meta:
        model = Finding_Group
        fields = ("id", "name", "test", "jira_issue")


class FindingMetaSerializer(serializers.ModelSerializer):
    class Meta:
        model = DojoMeta
        fields = ("name", "value")


class FindingProdTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_Type
        fields = ["id", "name"]


class FindingProductSerializer(serializers.ModelSerializer):
    prod_type = FindingProdTypeSerializer(required=False)

    class Meta:
        model = Product
        fields = ["id", "name", "prod_type"]


class FindingEngagementSerializer(serializers.ModelSerializer):
    product = FindingProductSerializer(required=False)

    class Meta:
        model = Engagement
        fields = [
            "id",
            "name",
            "description",
            "product",
            "target_start",
            "target_end",
            "branch_tag",
            "engagement_type",
            "build_id",
            "commit_hash",
            "version",
            "created",
            "updated",
        ]


class FindingEnvironmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Development_Environment
        fields = ["id", "name"]


class FindingTestTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Test_Type
        fields = ["id", "name"]


class FindingTestSerializer(serializers.ModelSerializer):
    engagement = FindingEngagementSerializer(required=False)
    environment = FindingEnvironmentSerializer(required=False)
    test_type = FindingTestTypeSerializer(required=False)

    class Meta:
        model = Test
        fields = [
            "id",
            "title",
            "test_type",
            "engagement",
            "environment",
            "branch_tag",
            "build_id",
            "commit_hash",
            "version",
        ]


class FindingRelatedFieldsSerializer(serializers.Serializer):
    test = serializers.SerializerMethodField()
    jira = serializers.SerializerMethodField()

    @extend_schema_field(FindingTestSerializer)
    def get_test(self, obj):
        return FindingTestSerializer(read_only=True).to_representation(
            obj.test,
        )

    @extend_schema_field(JIRAIssueSerializer)
    def get_jira(self, obj):
        issue = jira_services.get_issue(obj)
        if issue is None:
            return None
        return JIRAIssueSerializer(read_only=True).to_representation(issue)


class VulnerabilityIdSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability_Id
        fields = ["vulnerability_id"]


@extend_schema_field(serializers.CharField())
class CweField(serializers.Field):

    """Serialize a CWE as the canonical ``CWE-<n>`` string; accept ``"CWE-79"`` or ``"79"`` on write."""

    def to_representation(self, value):
        return cwe_label(value) or value

    def to_internal_value(self, data):
        label = cwe_label(data)
        if label is None:
            msg = "Enter a CWE number, e.g. 89 or CWE-89."
            raise serializers.ValidationError(msg)
        return label


class FindingCweSerializer(serializers.ModelSerializer):
    cwe = CweField()

    class Meta:
        model = Finding_CWE
        fields = ["cwe"]


class FindingSerializer(serializers.ModelSerializer):
    mitigated = serializers.DateTimeField(required=False, allow_null=True)
    mitigated_by = serializers.PrimaryKeyRelatedField(required=False, allow_null=True, queryset=User.objects.all())
    request_response = serializers.SerializerMethodField()
    accepted_risks = serializers.SerializerMethodField()
    push_to_jira = serializers.BooleanField(default=False)
    found_by = serializers.PrimaryKeyRelatedField(
        queryset=Test_Type.objects.all(), many=True,
    )
    age = serializers.IntegerField(read_only=True)
    sla_days_remaining = serializers.IntegerField(read_only=True, allow_null=True)
    finding_meta = FindingMetaSerializer(read_only=True, many=True)
    related_fields = serializers.SerializerMethodField(allow_null=True)
    # for backwards compatibility
    jira_creation = serializers.SerializerMethodField(read_only=True, allow_null=True)
    jira_change = serializers.SerializerMethodField(read_only=True, allow_null=True)
    display_status = serializers.SerializerMethodField()
    finding_groups = FindingGroupSerializer(
        source="finding_group_set", many=True, read_only=True,
    )
    vulnerability_ids = VulnerabilityIdSerializer(
        source="vulnerability_id_set", many=True, required=False,
    )
    cwes = FindingCweSerializer(
        source="finding_cwe_set", many=True, required=False,
    )
    reporter = serializers.PrimaryKeyRelatedField(
        required=False, queryset=User.objects.all(),
    )
    endpoints = serializers.PrimaryKeyRelatedField(
        source="locations",
        many=True,
        required=False,
        queryset=LocationFindingReference.objects.all(),
    )

    class Meta:
        model = Finding
        exclude = (
            "cve",
            "inherited_tags",
        )

    def get_fields(self):
        from dojo.api_v2.serializers import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            TagListSerializerField,
        )
        fields = super().get_fields()
        fields["tags"] = TagListSerializerField(required=False)
        return fields

    # TODO: Delete this after the move to Locations
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not settings.V3_FEATURE_LOCATIONS:
            self.fields["endpoints"] = serializers.PrimaryKeyRelatedField(
                many=True, required=False, queryset=Endpoint.objects.all(),
            )

    def get_accepted_risks(self, obj):
        from dojo.api_v2.serializers import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            RiskAcceptanceSerializer,
        )
        # schema annotation applied lazily at module bottom (avoids circular import)
        request = self.context.get("request")
        if request is None:
            return []
        if not user_has_permission(request.user, obj, "edit"):
            return []
        return RiskAcceptanceSerializer(
            obj.risk_acceptance_set.all(), many=True,
        ).data

    @extend_schema_field(serializers.DateTimeField())
    def get_jira_creation(self, obj):
        return jira_services.get_creation(obj)

    @extend_schema_field(serializers.DateTimeField())
    def get_jira_change(self, obj):
        return jira_services.get_change(obj)

    @extend_schema_field(FindingRelatedFieldsSerializer)
    def get_related_fields(self, obj):
        request = self.context.get("request", None)
        if request is None:
            return None

        query_params = request.query_params
        if query_params.get("related_fields", "false") == "true":
            return FindingRelatedFieldsSerializer(
                required=False,
            ).to_representation(obj)
        return None

    def get_display_status(self, obj) -> str:
        return obj.status()

    def process_risk_acceptance(self, data):
        import dojo.risk_acceptance.helper as ra_helper  # noqa: PLC0415 -- lazy import, avoids circular dependency
        is_risk_accepted = data.get("risk_accepted")
        # Do not take any action if the `risk_accepted` was not passed
        if not isinstance(is_risk_accepted, bool):
            return
        # Determine how to proceed based on the value of `risk_accepted`
        if is_risk_accepted and not self.instance.risk_accepted and self.instance.test.engagement.product.enable_simple_risk_acceptance and not data.get("active", False):
            ra_helper.simple_risk_accept(self.context["request"].user, self.instance)
        elif not is_risk_accepted and self.instance.risk_accepted:  # turning off risk_accepted
            ra_helper.risk_unaccept(self.context["request"].user, self.instance)

    # Overriding this to push add Push to JIRA functionality
    def update(self, instance, validated_data):
        # push_all_issues already checked in api views.py
        push_to_jira = validated_data.pop("push_to_jira")

        # Save vulnerability ids and pop them
        parsed_vulnerability_ids = []
        if (vulnerability_ids := validated_data.pop("vulnerability_id_set", None)):
            logger.debug("VULNERABILITY_ID_SET: %s", vulnerability_ids)
            parsed_vulnerability_ids.extend(vulnerability_id["vulnerability_id"] for vulnerability_id in vulnerability_ids)
            logger.debug("SETTING CVE FROM VULNERABILITY_ID_SET: %s", parsed_vulnerability_ids[0])
            validated_data["cve"] = parsed_vulnerability_ids[0]

        # CWEs (mirror vulnerability_ids): the first entry is the primary Finding.cwe; the rest
        # become Finding_CWE rows via save_cwes() below.
        parsed_cwes = None
        if (cwes := validated_data.pop("finding_cwe_set", None)) is not None:
            parsed_cwes = [entry["cwe"] for entry in cwes]
            validated_data["cwe"] = cwe_number(parsed_cwes[0]) if parsed_cwes else 0

        # Save the reporter on the finding
        if reporter_id := validated_data.get("reporter"):
            instance.reporter = reporter_id

        # Persist vulnerability IDs first so model save computes hash including them (if there is no hash yet)
        # we can't pass unsaved_vulnerabilitiy_ids to super.update()
        if parsed_vulnerability_ids:
            save_vulnerability_ids(instance, parsed_vulnerability_ids)

        # Get found_by from validated_data
        found_by = validated_data.pop("found_by", None)
        # Handle updates to found_by data
        if found_by:
            instance.found_by.set(found_by)
        # If there is no argument entered for found_by, the user would like to clear out the values on the Finding's found_by field
        # Findings still maintain original found_by value associated with their test
        # In the event the user does not supply the found_by field at all, we do not modify it
        elif isinstance(found_by, list) and len(found_by) == 0:
            instance.found_by.clear()

        locations = None
        if settings.V3_FEATURE_LOCATIONS:
            locations = validated_data.pop("locations", None)

        instance = super().update(
            instance, validated_data,
        )

        # Sync the CWE relation (separate from vulnerability ids) after the new cwe is applied.
        if parsed_cwes is not None:
            instance.unsaved_cwes = parsed_cwes[1:]
        save_cwes(instance)

        if settings.V3_FEATURE_LOCATIONS and locations is not None:
            for location_ref in instance.locations.all():
                location_ref.location.disassociate_from_finding(instance)
            for location_ref in locations:
                location_ref.location.associate_with_finding(instance)

        if push_to_jira or jira_services.is_keep_in_sync(instance):
            # Push synchronously so that we can see jira errors in real time
            success, message = jira_services.push(instance, force_sync=True)
            if not success:
                raise serializers.ValidationError(message)

        return instance

    def validate(self, data):
        # Enforce mitigated metadata editability (only when non-null values are provided)
        attempting_to_set_mitigated = any(
            (field in data) and (data.get(field) is not None)
            for field in ["mitigated", "mitigated_by"]
        )
        user = getattr(self.context.get("request", None), "user", None)
        if attempting_to_set_mitigated and not finding_helper.can_edit_mitigated_data(user):
            errors = {}
            if ("mitigated" in data) and (data.get("mitigated") is not None):
                errors["mitigated"] = ["Editing mitigated timestamp is disabled (EDITABLE_MITIGATED_DATA=false)"]
            if ("mitigated_by" in data) and (data.get("mitigated_by") is not None):
                errors["mitigated_by"] = ["Editing mitigated_by is disabled (EDITABLE_MITIGATED_DATA=false)"]
            if errors:
                raise serializers.ValidationError(errors)

        if self.context["request"].method == "PATCH":
            is_active = data.get("active", self.instance.active)
            is_verified = data.get("verified", self.instance.verified)
            is_duplicate = data.get("duplicate", self.instance.duplicate)
            is_false_p = data.get("false_p", self.instance.false_p)
            is_risk_accepted = data.get(
                "risk_accepted", self.instance.risk_accepted,
            )
        else:
            is_active = data.get("active", True)
            is_verified = data.get("verified", False)
            is_duplicate = data.get("duplicate", False)
            is_false_p = data.get("false_p", False)
            is_risk_accepted = data.get("risk_accepted", False)

        if (is_active or is_verified) and is_duplicate:
            msg = "Duplicate findings cannot be verified or active"
            raise serializers.ValidationError(msg)
        if is_false_p and is_verified:
            msg = "False positive findings cannot be verified."
            raise serializers.ValidationError(msg)

        if is_risk_accepted and not self.instance.risk_accepted:
            if (
                not self.instance.test.engagement.product.enable_simple_risk_acceptance
            ):
                msg = "Simple risk acceptance is disabled for this product, use the UI to accept this finding."
                raise serializers.ValidationError(msg)

        if is_active and is_risk_accepted:
            msg = "Active findings cannot be risk accepted."
            raise serializers.ValidationError(msg)

        # assuming we made it past the validations,call risk acceptance properly to make sure notes, etc get created
        # doing it here instead of in update because update doesn't know if the value changed
        self.process_risk_acceptance(data)

        return data

    def validate_severity(self, value: str) -> str:
        if value not in SEVERITIES:
            msg = f"Severity must be one of the following: {SEVERITIES}"
            raise serializers.ValidationError(msg)
        return value

    def build_relational_field(self, field_name, relation_info):
        from dojo.api_v2.serializers import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            NoteSerializer,
        )
        if field_name == "notes":
            return NoteSerializer, {"many": True, "read_only": True}
        return super().build_relational_field(field_name, relation_info)

    def get_request_response(self, obj):
        # Not necessarily Burp scan specific - these are just any request/response pairs
        burp_req_resp = obj.burprawrequestresponse_set.all()
        var = settings.MAX_REQRESP_FROM_API
        if var > -1:
            burp_req_resp = burp_req_resp[:var]
        burp_list = []
        for burp in burp_req_resp:
            request = burp.get_request()
            response = burp.get_response()
            burp_list.append({"request": request, "response": response})
        serialized_burps = BurpRawRequestResponseSerializer(
            {"req_resp": burp_list},
        )
        return serialized_burps.data


class FindingCreateSerializer(serializers.ModelSerializer):
    mitigated = serializers.DateTimeField(required=False, allow_null=True)
    mitigated_by = serializers.PrimaryKeyRelatedField(required=False, allow_null=True, queryset=User.objects.all())
    notes = serializers.PrimaryKeyRelatedField(
        read_only=True, allow_null=True, required=False, many=True,
    )
    test = serializers.PrimaryKeyRelatedField(queryset=Test.objects.all())
    thread_id = serializers.IntegerField(default=0)
    found_by = serializers.PrimaryKeyRelatedField(
        queryset=Test_Type.objects.all(), many=True,
    )
    url = serializers.CharField(allow_null=True, default=None)
    push_to_jira = serializers.BooleanField(default=False)
    vulnerability_ids = VulnerabilityIdSerializer(
        source="vulnerability_id_set", many=True, required=False,
    )
    cwes = FindingCweSerializer(
        source="finding_cwe_set", many=True, required=False,
    )
    reporter = serializers.PrimaryKeyRelatedField(
        required=False, queryset=User.objects.all(),
    )

    class Meta:
        model = Finding
        exclude = (
            "cve",
            "inherited_tags",
        )
        extra_kwargs = {
            "active": {"required": True},
            "verified": {"required": True},
        }

    def get_fields(self):
        from dojo.api_v2.serializers import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            TagListSerializerField,
        )
        fields = super().get_fields()
        fields["tags"] = TagListSerializerField(required=False)
        return fields

    # Overriding this to push add Push to JIRA functionality
    def create(self, validated_data):
        logger.debug("Creating finding with validated data: %s", validated_data)
        push_to_jira = validated_data.pop("push_to_jira", False)
        notes = validated_data.pop("notes", None)
        found_by = validated_data.pop("found_by", None)
        reviewers = validated_data.pop("reviewers", None)
        # Process the vulnerability IDs specially
        parsed_vulnerability_ids = []
        if (vulnerability_ids := validated_data.pop("vulnerability_id_set", None)):
            logger.debug("VULNERABILITY_ID_SET: %s", vulnerability_ids)
            parsed_vulnerability_ids.extend(vulnerability_id["vulnerability_id"] for vulnerability_id in vulnerability_ids)
            logger.debug("PARSED_VULNERABILITY_IDST: %s", parsed_vulnerability_ids)
            logger.debug("SETTING CVE FROM VULNERABILITY_ID_SET: %s", parsed_vulnerability_ids[0])
            validated_data["cve"] = parsed_vulnerability_ids[0]
            # validated_data["unsaved_vulnerability_ids"] = parsed_vulnerability_ids

        # CWEs (mirror vulnerability_ids): first entry is the primary cwe, the rest are extras.
        parsed_cwes = None
        if (cwes := validated_data.pop("finding_cwe_set", None)) is not None:
            parsed_cwes = [entry["cwe"] for entry in cwes]
            validated_data["cwe"] = cwe_number(parsed_cwes[0]) if parsed_cwes else 0

        # super.create() doesn't accept unsaved_vulnerability_ids or dedupe_option=False, so call save directly.
        new_finding = Finding(**validated_data)
        new_finding.unsaved_vulnerability_ids = parsed_vulnerability_ids or []
        new_finding.save()

        logger.debug(f"New finding CVE: {new_finding.cve}")

        # Deal with all of the many to many things
        if notes:
            new_finding.notes.set(notes)
        if found_by:
            new_finding.found_by.set(found_by)
        if reviewers:
            new_finding.reviewers.set(reviewers)
        if parsed_vulnerability_ids:
            save_vulnerability_ids(new_finding, parsed_vulnerability_ids)
        if parsed_cwes is not None:
            new_finding.unsaved_cwes = parsed_cwes[1:]
        save_cwes(new_finding)

        if push_to_jira:
            jira_services.push(new_finding)

        # Create a notification
        dojo_dispatch_task(
            async_create_notification,
            event="finding_added",
            title=_("Addition of %s") % new_finding.title,
            finding_id=new_finding.id,
            description=_('Finding "%s" was added by %s') % (new_finding.title, new_finding.reporter),
            url=reverse("view_finding", args=(new_finding.id,)),
            icon="exclamation-triangle",
        )

        return new_finding

    def validate(self, data):
        # Ensure mitigated fields are only set when editable is enabled (ignore nulls)
        attempting_to_set_mitigated = any(
            (field in data) and (data.get(field) is not None)
            for field in ["mitigated", "mitigated_by"]
        )
        user = getattr(getattr(self.context, "request", None), "user", None)
        if attempting_to_set_mitigated and not finding_helper.can_edit_mitigated_data(user):
            errors = {}
            if ("mitigated" in data) and (data.get("mitigated") is not None):
                errors["mitigated"] = ["Editing mitigated timestamp is disabled (EDITABLE_MITIGATED_DATA=false)"]
            if ("mitigated_by" in data) and (data.get("mitigated_by") is not None):
                errors["mitigated_by"] = ["Editing mitigated_by is disabled (EDITABLE_MITIGATED_DATA=false)"]
            if errors:
                raise serializers.ValidationError(errors)

        if "reporter" not in data:
            request = self.context["request"]
            data["reporter"] = request.user

        if (data.get("active") or data.get("verified")) and data.get(
            "duplicate",
        ):
            msg = "Duplicate findings cannot be verified or active"
            raise serializers.ValidationError(msg)
        if data.get("false_p") and data.get("verified"):
            msg = "False positive findings cannot be verified."
            raise serializers.ValidationError(msg)

        if "risk_accepted" in data and data.get("risk_accepted"):
            test = data.get("test")
            # test = Test.objects.get(id=test_id)
            if not test.engagement.product.enable_simple_risk_acceptance:
                msg = "Simple risk acceptance is disabled for this product, use the UI to accept this finding."
                raise serializers.ValidationError(msg)

        if (
            data.get("active")
            and "risk_accepted" in data
            and data.get("risk_accepted")
        ):
            msg = "Active findings cannot be risk accepted."
            raise serializers.ValidationError(msg)

        return data

    def validate_severity(self, value: str) -> str:
        if value not in SEVERITIES:
            msg = f"Severity must be one of the following: {SEVERITIES}"
            raise serializers.ValidationError(msg)
        return value


class FindingTemplateSerializer(serializers.ModelSerializer):
    vulnerability_ids = serializers.SerializerMethodField()
    endpoints = serializers.SerializerMethodField()

    class Meta:
        model = Finding_Template
        exclude = ("cve", "vulnerability_ids_text")

    def get_fields(self):
        from dojo.api_v2.serializers import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            TagListSerializerField,
        )
        fields = super().get_fields()
        fields["tags"] = TagListSerializerField(required=False)
        return fields

    @extend_schema_field(serializers.ListField(child=serializers.CharField()))
    def get_vulnerability_ids(self, obj):
        """Return vulnerability IDs as a list of strings."""
        return obj.vulnerability_ids

    @extend_schema_field(serializers.ListField(child=serializers.CharField()))
    def get_endpoints(self, obj):
        """Return endpoints as a list of URL strings."""
        return obj.endpoints if hasattr(obj, "endpoints") else []

    def create(self, validated_data):

        # Handle vulnerability_ids if provided as list
        vulnerability_ids = None
        if "vulnerability_ids" in self.initial_data:
            vulnerability_ids = self.initial_data.get("vulnerability_ids", [])
            if isinstance(vulnerability_ids, str):
                # If it's a string, split by newlines
                vulnerability_ids = [vid.strip() for vid in vulnerability_ids.split("\n") if vid.strip()]
            elif not isinstance(vulnerability_ids, list):
                vulnerability_ids = []

        # Handle endpoints if provided as list
        endpoint_urls = None
        if "endpoints" in self.initial_data:
            endpoint_urls = self.initial_data.get("endpoints", [])
            if isinstance(endpoint_urls, str):
                # If it's a string, split by newlines
                endpoint_urls = [url.strip() for url in endpoint_urls.split("\n") if url.strip()]
            elif not isinstance(endpoint_urls, list):
                endpoint_urls = []

        new_finding_template = super().create(
            validated_data,
        )

        # Save vulnerability IDs using helper
        if vulnerability_ids:
            save_vulnerability_ids_template(new_finding_template, vulnerability_ids)

        # Save endpoints using helper
        if endpoint_urls:
            save_endpoints_template(new_finding_template, endpoint_urls)

        return new_finding_template

    def update(self, instance, validated_data):
        # Handle vulnerability_ids if provided
        if "vulnerability_ids" in self.initial_data:
            vulnerability_ids = self.initial_data.get("vulnerability_ids", [])
            if isinstance(vulnerability_ids, str):
                vulnerability_ids = [vid.strip() for vid in vulnerability_ids.split("\n") if vid.strip()]
            elif not isinstance(vulnerability_ids, list):
                vulnerability_ids = []
            save_vulnerability_ids_template(instance, vulnerability_ids)

        # Handle endpoints if provided
        if "endpoints" in self.initial_data:
            endpoint_urls = self.initial_data.get("endpoints", [])
            if isinstance(endpoint_urls, str):
                endpoint_urls = [url.strip() for url in endpoint_urls.split("\n") if url.strip()]
            elif not isinstance(endpoint_urls, list):
                endpoint_urls = []
            save_endpoints_template(instance, endpoint_urls)

        return super().update(instance, validated_data)


class FindingToNotesSerializer(serializers.Serializer):
    finding_id = serializers.PrimaryKeyRelatedField(
        queryset=Finding.objects.all(), many=False, allow_null=True,
    )

    def get_fields(self):
        from dojo.api_v2.serializers import NoteSerializer  # noqa: PLC0415 -- lazy import, avoids circular dependency
        fields = super().get_fields()
        fields["notes"] = NoteSerializer(many=True)
        return fields


class FindingToFilesSerializer(serializers.Serializer):
    finding_id = serializers.PrimaryKeyRelatedField(
        queryset=Finding.objects.all(), many=False, allow_null=True,
    )

    def get_fields(self):
        from dojo.api_v2.serializers import FileSerializer  # noqa: PLC0415 -- lazy import, avoids circular dependency
        fields = super().get_fields()
        fields["files"] = FileSerializer(many=True)
        return fields

    def to_representation(self, data):
        finding = data.get("finding_id")
        files = data.get("files")
        new_files = [{
                "id": file.id,
                "file": "{site_url}/{file_access_url}".format(
                    site_url=settings.SITE_URL,
                    file_access_url=file.get_accessible_url(
                        finding, finding.id,
                    ),
                ),
                "title": file.title,
            } for file in files]
        return {"finding_id": finding.id, "files": new_files}


class FindingCloseSerializer(serializers.ModelSerializer):
    is_mitigated = serializers.BooleanField(required=False)
    mitigated = serializers.DateTimeField(required=False)
    false_p = serializers.BooleanField(required=False)
    out_of_scope = serializers.BooleanField(required=False)
    duplicate = serializers.BooleanField(required=False)
    mitigated_by = serializers.PrimaryKeyRelatedField(required=False, allow_null=True, queryset=Dojo_User.objects.all())
    note = serializers.CharField(required=False, allow_blank=True)
    note_type = serializers.PrimaryKeyRelatedField(required=False, allow_null=True, queryset=Note_Type.objects.all())

    class Meta:
        model = Finding
        fields = (
            "is_mitigated",
            "mitigated",
            "false_p",
            "out_of_scope",
            "duplicate",
            "mitigated_by",
            "note",
            "note_type",
        )

    def validate(self, data):
        request = self.context.get("request")
        request_user = getattr(request, "user", None)

        mitigated_by_user = data.get("mitigated_by")
        if mitigated_by_user is not None:
            # Require permission to edit mitigated metadata
            if not (request_user and finding_helper.can_edit_mitigated_data(request_user)):
                raise serializers.ValidationError({
                    "mitigated_by": ["Not allowed to set mitigated_by."],
                })

            # Ensure selected user is authorized (Finding_Edit)
            authorized_users = get_authorized_users("edit", user=request_user)
            if not authorized_users.filter(id=mitigated_by_user.id).exists():
                raise serializers.ValidationError({
                    "mitigated_by": [
                        "Selected user is not authorized to be set as mitigated_by.",
                    ],
                })

        return data


class FindingVerifySerializer(serializers.Serializer):
    note = serializers.CharField(required=False, allow_blank=True)
    note_type = serializers.PrimaryKeyRelatedField(required=False, allow_null=True, queryset=Note_Type.objects.all())


class FindingNoteSerializer(serializers.Serializer):
    note_id = serializers.IntegerField()


def _apply_schema_overrides():
    # Apply @extend_schema_field annotations that reference serializers which remain
    # in dojo.api_v2.serializers. These are applied here (rather than as class-body
    # decorators) so the module carries no top-level dojo.api_v2.serializers import,
    # which would create a circular dependency. drf-spectacular only reads these
    # overrides at schema generation time, so applying them lazily on import is fine.
    from drf_spectacular.utils import set_override  # noqa: PLC0415 -- lazy import, avoids circular dependency

    from dojo.api_v2.serializers import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
        RiskAcceptanceSerializer,
    )
    set_override(FindingSerializer.get_accepted_risks, "field", RiskAcceptanceSerializer(many=True))
    set_override(FindingSerializer.get_request_response, "field", BurpRawRequestResponseSerializer)


_apply_schema_overrides()
