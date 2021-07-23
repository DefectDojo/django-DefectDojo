from abc import ABC, abstractmethod
from typing import NamedTuple, List

from django.db.models import QuerySet
from drf_spectacular.utils import extend_schema
from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema

from dojo.api_v2.serializers import RiskAcceptanceSerializer
from dojo.models import Risk_Acceptance, User
from django.utils import timezone
from dojo.authorization.roles_permissions import Permissions
from dojo.engagement.queries import get_authorized_engagements


AcceptedRisk = NamedTuple('AcceptedRisk', (('cve', str), ('justification', str), ('accepted_by', str)))


class AcceptedRiskSerializer(serializers.Serializer):
    cve = serializers.CharField(max_length=28, label='CVE', help_text='CVE or vulnerability id to accept findings for')
    justification = serializers.CharField(help_text='Justification for accepting findings with this CVE')
    accepted_by = serializers.CharField(max_length=200, help_text='Name or email of person who accepts the risk')

    def create(self, validated_data):
        return AcceptedRisk(**validated_data)


class AcceptedRisksMixin(ABC):

    @property
    @abstractmethod
    def risk_application_model_class(self):
        pass

    @swagger_auto_schema(
        request_body=AcceptedRiskSerializer(many=True),
        responses={status.HTTP_201_CREATED: RiskAcceptanceSerializer(many=True)},
    )
    @extend_schema(
        request=AcceptedRiskSerializer(many=True),
        responses={status.HTTP_201_CREATED: RiskAcceptanceSerializer(many=True)},
    )
    @action(methods=['post'], detail=True, permission_classes=[IsAdminUser], serializer_class=AcceptedRiskSerializer,
            filter_backends=[], pagination_class=None)
    def accept_risks(self, request, pk=None):
        model = self.get_object()
        serializer = AcceptedRiskSerializer(data=request.data, many=True)
        if serializer.is_valid():
            accepted_risks = serializer.save()
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        base_findings = model.unaccepted_open_findings
        owner = request.user
        accepted = _accept_risks(accepted_risks, base_findings, owner)
        model.accept_risks(accepted)
        result = RiskAcceptanceSerializer(instance=accepted, many=True)
        return Response(status=status.HTTP_201_CREATED, data=result.data)


class AcceptedFindingsMixin(ABC):

    @swagger_auto_schema(
        request_body=AcceptedRiskSerializer(many=True),
        responses={status.HTTP_201_CREATED: RiskAcceptanceSerializer(many=True)},
    )
    @extend_schema(
        request=AcceptedRiskSerializer(many=True),
        responses={status.HTTP_201_CREATED: RiskAcceptanceSerializer(many=True)},
    )
    @action(methods=['post'], detail=False, permission_classes=[IsAdminUser], serializer_class=AcceptedRiskSerializer)
    def accept_risks(self, request):
        serializer = AcceptedRiskSerializer(data=request.data, many=True)
        if serializer.is_valid():
            accepted_risks = serializer.save()
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        owner = request.user
        accepted_result = []
        for engagement in get_authorized_engagements(Permissions.Engagement_View):
            base_findings = engagement.unaccepted_open_findings
            accepted = _accept_risks(accepted_risks, base_findings, owner)
            engagement.accept_risks(accepted)
            accepted_result.extend(accepted)
        result = RiskAcceptanceSerializer(instance=accepted_result, many=True)
        return Response(status=201, data=result.data)


def _accept_risks(accepted_risks: List[AcceptedRisk], base_findings: QuerySet, owner: User):
    accepted = []
    for risk in accepted_risks:
        findings = base_findings.filter(cve=risk.cve)
        if findings.exists():
            # TODO we could use risk.cve to name the risk_acceptance, but would need to check for existing risk_acceptances in that case
            # so for now we add some timestamp based suffix
            name = risk.cve + ' via api at ' + timezone.now().strftime('%b %d, %Y, %H:%M:%S')
            acceptance = Risk_Acceptance.objects.create(owner=owner, name=name[:100],
                                                        decision=Risk_Acceptance.TREATMENT_ACCEPT,
                                                        decision_details=risk.justification,
                                                        accepted_by=risk.accepted_by[:200])
            acceptance.accepted_findings.set(findings)
            findings.update(risk_accepted=True)
            acceptance.save()
            accepted.append(acceptance)

    return accepted
