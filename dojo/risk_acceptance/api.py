from typing import List, NamedTuple, Union

from rest_framework import serializers

from dojo.models import Product_Type, Product, Engagement, Test, Finding, Risk_Acceptance, User

AcceptedRisk = NamedTuple('AcceptedRisk', (('cve', str), ('justification', str), ('accepted_by', str)))


class AcceptedRiskSerializer(serializers.Serializer):
    cve = serializers.CharField(max_length=28, label='CVE', help_text='CVE or vulnerability id to accept findings for')
    justification = serializers.CharField(help_text='Justification for accepting findings with this CVE')
    accepted_by = serializers.CharField(max_length=200, help_text='Name or email of person who accepts the risk')

    def create(self, validated_data):
        return AcceptedRisk(**validated_data)


def accept_findings_matching(risks: List[AcceptedRisk], reporter: User,
                             model: Union[Product_Type, Product, Engagement, Test, None]) \
        -> List[Risk_Acceptance]:
    if model is None:
        base_findings = Finding.unaccepted_open_findings()
    else:
        base_findings = model.unaccepted_open_findings
    accepted = []
    for risk in risks:
        findings = base_findings.filter(cve=risk.cve)
        if findings.exists():
            acceptance = Risk_Acceptance.objects.create(reporter=reporter,
                                                        compensating_control=risk.justification,
                                                        accepted_by=risk.accepted_by)
            acceptance.accepted_findings.set(findings)
            acceptance.save()
            accepted.append(acceptance)

    if model is None:
        for engagement in Engagement.objects.all():
            engagement.accept_risks(accepted)
    else:
        model.accept_risks(accepted)

    return accepted
