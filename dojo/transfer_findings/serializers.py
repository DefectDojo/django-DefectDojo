from rest_framework import serializers
from dojo.authorization.roles_permissions import Permissions
from dojo.models import TransferFinding, Finding, TransferFindingFinding
from dojo.authorization.authorization import user_has_permission, user_has_global_permission


class FindingTfSerlilizer(serializers.ModelSerializer):
    class Meta:
        model = Finding 
        fields = '__all__'

class TransferFindingFindingsSerializer(serializers.ModelSerializer):
    findings = FindingTfSerlilizer(read_only=True)

    class Meta:
        model = TransferFindingFinding
        fields = '__all__'


class TransferFindingFindingSerializer(serializers.ModelSerializer):
    findings = FindingTfSerlilizer(read_only=True)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['permission'] = []
        transfer_finding_finding_obj = TransferFindingFinding.objects.get(id=representation['id'])
        for permission in [Permissions.Transfer_Finding_Finding_View,
                        Permissions.Transfer_Finding_Finding_Edit,
                        Permissions.Transfer_Finding_Finding_Delete,
                        Permissions.Transfer_Finding_Finding_Add]:
            user = self.context["request"].user

            if user.is_superuser:
                representation['permission'].append(permission)

            elif user_has_global_permission(user, permission):
                representation['permission'].append(permission)

            elif user_has_permission(
                    self.context["request"].user,
                    transfer_finding_finding_obj,
                    permission):
                if(transfer_finding_finding_obj.findings.risk_status == "Transfer Accepted"
                   and permission == Permissions.Transfer_Finding_Finding_View):
                    representation['permission'].append(permission)
                elif transfer_finding_finding_obj.findings.risk_status in ["Transfer Rejected", "Transfer Pending"]:
                    representation['permission'].append(permission)

        return representation
            

    class Meta:
        model = TransferFindingFinding
        fields = '__all__'


class TransferFindingSerializer(serializers.ModelSerializer):

    transfer_findings = TransferFindingFindingSerializer(many=True)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['permission'] = []
        transfer_finding_obj = TransferFinding.objects.get(id=representation.get("id"))
        all_permissions = [Permissions.Transfer_Finding_View,
                           Permissions.Transfer_Finding_Edit,
                           Permissions.Transfer_Finding_Delete,
                           Permissions.Transfer_Finding_Add]
        user = self.context["request"].user
        for permission in all_permissions:
            if user.is_superuser:
                representation['permission'].append(permission)

            elif user_has_global_permission(user, permission):
                representation['permission'].append(permission)

            elif user_has_permission(
                    user,
                    transfer_finding_obj,
                    permission):
                transfer_finding_finding = transfer_finding_obj.transfer_findings.filter(findings__risk_status="Transfer Accepted")
                if transfer_finding_finding:
                    if permission == Permissions.Transfer_Finding_View:
                        representation['permission'].append(permission)

        return representation

    class Meta:
        model = TransferFinding
        fields = "__all__"