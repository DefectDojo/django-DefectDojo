import logging
from crum import get_current_user
from dojo.utils import get_product, user_is_contacts
from dojo.api_v2.api_error import ApiError
from rest_framework import serializers
from dojo.authorization.roles_permissions import Permissions
from dojo.models import TransferFinding, Finding, TransferFindingFinding, Product, Product_Type, Engagement, Dojo_User
from dojo.authorization.authorization import user_has_permission, user_has_global_permission
from dojo.authorization.exclusive_permissions import user_has_exclusive_permission

logger = logging.getLogger(__name__)


class FindingTfSerlilizer(serializers.ModelSerializer):
    
    def to_representation(self, instance):
        if not user_has_exclusive_permission(
            user=None,
            obj=instance,
            permission=Permissions.Product_Tag_Red_Team
            ):
            return None
        representation = super().to_representation(instance)
        representation["tags"] = [tag.name for tag in instance.tags.all()]
        return representation
    class Meta:
        model = Finding 
        fields = [
            "id",
            "priority",
            "priority_classification",
            "severity",
            "risk_status",
            "title",
            "status",
            "cve",
            "cwe",
            "date",
            "reporter",
            "found_by",
            "service"
        ]


class TransferFindingFindingCreateSerializer(serializers.ModelSerializer):
    findings = serializers.PrimaryKeyRelatedField(queryset=Finding.objects.all(), required=True, many=True, write_only=True)
    class Meta:
        model = TransferFindingFinding
        fields = '__all__'
    
    def create(self, validation_data):
        # add finding to Transfer Finding
        self.assignment_of_origin_of_finding(validation_data["findings"], validation_data)
        transfer_finding_request = validation_data["transfer_findings"]
        destination_engagement = transfer_finding_request.destination_engagement
        findings = validation_data.pop("findings")
        tf_list = []
        for finding in findings:
            if finding.risk_status is not None:
                finding.risk_status = finding.risk_status.strip()
            if finding.risk_status not in ["Risk Active", None, ""]:
                message = "The finding status must be Risk Active, Finding ID: " + str(finding.id)
                logger.error(message)
                raise ApiError.precondition_required(message)
            if TransferFindingFinding.objects.filter(findings=finding.id).exists():
                message = "It is not possible to transfer to a finding that has already been transferred. Finding ID: " + str(finding.id)
                logger.error(message)
                raise ApiError.precondition_required(message)
            if destination_engagement is not None and finding.test.engagement.id == destination_engagement.id:
                message = "It is not possible to transfer to a finding the same engagement." + f"Finding {finding.id}, engagment_id: {destination_engagement.id}"
                logger.error(message)
                raise ApiError.precondition_required(message)
            finding.risk_status = "Transfer Pending"
            finding.save()
            transfer_finding_finding = TransferFindingFinding.objects.create(
                    findings=finding,
                    transfer_findings=transfer_finding_request,
                    finding_related=validation_data.get("finding_related", None))
            tf_list.append(transfer_finding_finding) 
        return tf_list
    
    def assignment_of_origin_of_finding(self, findings, validation_data):
        origin_engagement = findings[0].test.engagement
        origin_product = origin_engagement.product
        origin_product_type = origin_product.prod_type
        transfer_finding = validation_data["transfer_findings"]
        transfer_finding.origin_product = origin_product
        transfer_finding.origin_product_type = origin_product_type
        transfer_finding.origin_engagement = origin_engagement
        transfer_finding.save()
        validation_data["origin_product"] = origin_product
        validation_data["origin_product_type"] = origin_product_type
        validation_data["origin_engagement"] = origin_engagement


class TransferFindingBasicSerializer(serializers.ModelSerializer):
    destination_product_type = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Product_Type.objects.all(),
        required=False,
        allow_null=True
    )
    destination_product = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Product.objects.all(),
        required=False,
        allow_null=True
    )
    destination_engagement = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Engagement.objects.all(),
        required=False,
        allow_null=True
    )
    origin_product_type = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Product_Type.objects.all(),
        required=False,
        allow_null=True
    )
    origin_product = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Product.objects.all(),
        required=False,
        allow_null=True
    )
    origin_engagement = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Engagement.objects.all(),
        required=False,
        allow_null=True
    )
    accepted_by = serializers.SlugRelatedField(
        slug_field='username',
        queryset=Dojo_User.objects.all(),
        required=False,
        allow_null=True
    )
    status = serializers.SerializerMethodField()
    class Meta:
        model = TransferFinding
        fields = [
              "id",
            "title",
            "date",
            "notes",
            "expiration_date",
            "destination_product_type",
            "destination_product",
            "destination_engagement",
            "origin_product_type",
            "origin_product",
            "origin_engagement",
            "accepted_by",
            "status",
            "owner"
        ]
    
    def get_status(self, obj):
        """Status of the transfer finding based on the risk status of transfer_finding_finding"""
        statuses = obj.transfer_findings.prefetch_related("findings").values_list("findings__risk_status", flat=True)
        statuses = set(statuses)
        if not statuses:        
            return "No Findings"
        if "Transfer Pending" in statuses:
            return "Transfer Pending"
        if "Transfer Expired" in statuses:
            return "Transfer Expired"
        if "Transfer Rejected" in statuses:
            return "Transfer Rejected"
        if "Risk Active" in statuses:
            return "Risk Active"
        if "Transfer Accepted" in statuses:
            return "Transfer Accepted"
        return statuses.pop()

class TransferFindingFindingSerializer(serializers.ModelSerializer):
    findings = FindingTfSerlilizer(read_only=True)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['permissions'] = []
        transfer_finding_finding_obj = TransferFindingFinding.objects.get(id=representation['id'])
        for permission in [Permissions.Transfer_Finding_Finding_View,
                        Permissions.Transfer_Finding_Finding_Edit,
                        Permissions.Transfer_Finding_Finding_Delete,
                        Permissions.Transfer_Finding_Finding_Add]:
            user = self.context["request"].user

            if user.is_superuser:
                representation['permissions'].append(permission.name)

            elif user_has_global_permission(user, permission):
                representation['permissions'].append(permission.name)
            
            elif user_is_contacts(user, transfer_finding_finding_obj.transfer_findings.destination_product):
                if (
                    transfer_finding_finding_obj.findings.risk_status in ["Transfer Accepted", "Transfer Expired", "Risk Active"]
                    and permission in [Permissions.Transfer_Finding_Finding_View]
                ):
                    representation['permissions'].append(permission.name)
                    break
                representation['permissions'].append(permission.name)

            elif user_has_permission(
                    self.context["request"].user,
                    transfer_finding_finding_obj,
                    permission):
                if(transfer_finding_finding_obj.findings.risk_status == "Transfer Accepted"
                   and permission == Permissions.Transfer_Finding_Finding_View):
                    representation['permissions'].append(permission.name)
                elif transfer_finding_finding_obj.findings.risk_status in ["Transfer Rejected", "Transfer Pending"]:
                    representation['permissions'].append(permission.name)

        return representation
            

    class Meta:
        model = TransferFindingFinding
        fields = '__all__'

class TransferFindingUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = TransferFinding
        fields = "__all__"
        read_only_fields = [
            "origin_product_type",
            "origin_product",
            "origin_engagement",
        ]
    
class TransferFindingCreateSerializer(serializers.ModelSerializer):
    owner = serializers.CharField(required=False)
    class Meta:
        model = TransferFinding
        fields = "__all__"
    
    def create(self, validated_data) :
        if validated_data.get("owner") is None:
            user = get_current_user()
            validated_data["owner"] = user
        return super().create(validated_data)

class TransferFindingSerializer(serializers.ModelSerializer):

    transfer_findings = TransferFindingFindingSerializer(many=True)
    destination_product_type = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Product_Type.objects.all(),
        required=False,
        allow_null=True
    )
    destination_product = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Product.objects.all(),
        required=False,
        allow_null=True
    )
    destination_product_id = serializers.PrimaryKeyRelatedField(required=False, read_only=True)
    destination_engagement = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Engagement.objects.all(),
        required=False,
        allow_null=True
    )
    origin_product_type = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Product_Type.objects.all(),
        required=False,
        allow_null=True
    )
    origin_product = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Product.objects.all(),
        required=False,
        allow_null=True
    )
    origin_engagement = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Engagement.objects.all(),
        required=False,
        allow_null=True
    )
    accepted_by = serializers.SlugRelatedField(
        slug_field='username',
        queryset=Dojo_User.objects.all(),
        required=False,
        allow_null=True
    )
    owner = serializers.SlugRelatedField(
        slug_field='username',
        queryset=Dojo_User.objects.all(),
        required=False,
        allow_null=True
    )

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['permissions'] = []
        transfer_finding_obj = TransferFinding.objects.get(id=representation.get("id"))
        all_permissions = [Permissions.Transfer_Finding_View,
                           Permissions.Transfer_Finding_Edit,
                           Permissions.Transfer_Finding_Delete,
                           Permissions.Transfer_Finding_Add]
        user = self.context["request"].user
        for permission in all_permissions:
            if user.is_superuser:
                representation['permissions'].append(permission.name)

            elif user_has_global_permission(user, permission):
                representation['permissions'].append(permission.name)

            elif user_is_contacts(user, transfer_finding_obj.destination_product):
                serializer = TransferFindingBasicSerializer(instance=transfer_finding_obj, context={"request": self.context["request"]})
                if serializer.data.get("status") in ["Transfer Accepted", "Transfer Expired", "Risk Active"] and permission in [
                    Permissions.Transfer_Finding_View,
                    Permissions.Transfer_Finding_Finding_View
                ]:
                    representation['permissions'].append(permission.name)
                    break
                else:
                    representation['permissions'].append(permission.name)

            elif user_has_permission(
                    user,
                    transfer_finding_obj,
                    permission):
                transfer_finding_finding = transfer_finding_obj.transfer_findings.filter(findings__risk_status="Transfer Accepted")
                if transfer_finding_finding:
                    if permission == Permissions.Transfer_Finding_View:
                        representation['permissions'].append(permission.name)

        return representation

    class Meta:
        model = TransferFinding
        fields = [
            "id",
            "title",
            "date",
            "notes",
            "expiration_date",
            "destination_product_type",
            "destination_product",
            "destination_product_id",
            "destination_engagement",
            "origin_product_type",
            "origin_product",
            "origin_engagement",
            "accepted_by",
            "owner",
            "transfer_findings"
        ]


class TransferFindingFindingsSerializer(serializers.ModelSerializer):
    findings = FindingTfSerlilizer(read_only=True)
    transfer_findings = TransferFindingBasicSerializer(read_only=True)

    class Meta:
        model = TransferFindingFinding
        fields = "__all__"