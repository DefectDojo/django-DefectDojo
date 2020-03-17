from abc import ABC, abstractmethod
from typing import NamedTuple, List

from django.db.models import QuerySet
from django.shortcuts import get_object_or_404
from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response

from dojo.api_v2.serializers import RiskAcceptanceSerializer
from dojo.models import Engagement, Risk_Acceptance, User

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

    @action(methods=['post'], detail=True, permission_classes=[IsAdminUser], serializer_class=AcceptedRiskSerializer)
    def accept_risks(self, request, pk=None):
        model = get_object_or_404(self.risk_application_model_class, pk=pk)
        serializer = AcceptedRiskSerializer(data=request.data, many=True)
        if serializer.is_valid():
            accepted_risks = serializer.save()
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        base_findings = model.unaccepted_open_findings
        reporter = request.user
        accepted = _accept_risks(accepted_risks, base_findings, reporter)
        model.accept_risks(accepted)
        result = RiskAcceptanceSerializer(instance=accepted, many=True)
        return Response(result.data)


class AcceptedFindingsMixin(ABC):

    @action(methods=['post'], detail=False, permission_classes=[IsAdminUser], serializer_class=AcceptedRiskSerializer)
    def accept_risks(self, request):
        serializer = AcceptedRiskSerializer(data=request.data, many=True)
        if serializer.is_valid():
            accepted_risks = serializer.save()
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        reporter = request.user
        accepted_result = []
        for engagement in Engagement.objects.all():
            base_findings = engagement.unaccepted_open_findings
            accepted = _accept_risks(accepted_risks, base_findings, reporter)
            engagement.accept_risks(accepted)
            accepted_result.extend(accepted)
        result = RiskAcceptanceSerializer(instance=accepted_result, many=True)
        return Response(result.data)


def _accept_risks(accepted_risks: List[AcceptedRisk], base_findings: QuerySet, reporter: User):
    accepted = []
    for risk in accepted_risks:
        findings = base_findings.filter(cve=risk.cve)
        if findings.exists():
            acceptance = Risk_Acceptance.objects.create(reporter=reporter,
                                                        compensating_control=risk.justification,
                                                        accepted_by=risk.accepted_by)
            acceptance.accepted_findings.set(findings)
            acceptance.save()
            accepted.append(acceptance)
    return accepted
