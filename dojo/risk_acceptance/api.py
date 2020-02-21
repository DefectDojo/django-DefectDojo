from typing import List, NamedTuple, Union

from rest_framework import serializers

from dojo import models

AcceptedRisk = NamedTuple('AcceptedRisk', (('cve', str), ('justification', str), ('accepted_by', str)))


class AcceptedRiskSerializer(serializers.Serializer):
    cve = serializers.CharField(max_length=28, label='CVE', help_text='CVE or vulnerability id to accept findings for')
    justification = serializers.CharField(help_text='Justification for accepting findings with this CVE')
    accepted_by = serializers.CharField(max_length=200, help_text='Name or email of person who accepts the risk')

    def create(self, validated_data):
        return AcceptedRisk(**validated_data)


def accept_findings_matching(risks: List[AcceptedRisk], reporter: models.User,
                             model: Union[models.Product_Type, models.Product, models.Engagement, models.Test, None]) \
        -> List[models.Risk_Acceptance]:
    if isinstance(model, models.Product_Type):
        prod_type_engagements = models.Engagement.objects.filter(product__prod_type=model)
        accepted_findings = models.Finding.objects.filter(risk_acceptance__engagement__in=prod_type_engagements)
    elif isinstance(model, models.Product):
        accepted_findings = models.Finding.objects.filter(risk_acceptance__engagement__in=model.engagement_set)
    elif isinstance(model, models.Engagement):
        accepted_findings = models.Finding.objects.filter(risk_acceptance__engagement=model)
    elif isinstance(model, models.Test):
        accepted_findings = models.Finding.objects.filter(risk_acceptance__engagement=model.engagement)
    else:
        accepted_findings = models.Finding.objects.exclude(risk_acceptance__isnull=True)
    accepted_ids = [f.id for f in accepted_findings.only('id')]
    base_findings = models.Finding.objects.filter(active=True, verified=True, duplicate=False).exclude(
        id__in=accepted_ids)
    accepted = []
    for risk in risks:
        if isinstance(model, models.Product_Type):
            findings = base_findings.filter(test__engagement__product__prod_type=model)
        elif isinstance(model, models.Product):
            findings = base_findings.filter(test__engagement__product=model)
        elif isinstance(model, models.Engagement):
            findings = base_findings.filter(test__engagement=model)
        elif isinstance(model, models.Test):
            findings = base_findings.filter(test=model)
        else:
            findings = base_findings
        findings = findings.filter(cve=risk.cve)
        if findings.exists():
            acceptance = models.Risk_Acceptance.objects.create(reporter=reporter,
                                                               compensating_control=risk.justification,
                                                               accepted_by=risk.accepted_by)
            acceptance.accepted_findings.set(findings)
            acceptance.save()
            accepted.append(acceptance)

    def add_risks_to_engagement(engagement: models.Engagement):
        engagement.risk_acceptance.add(*accepted)

    if isinstance(model, models.Product_Type):
        for eng in models.Engagement.objects.filter(product__prod_type=model):
            add_risks_to_engagement(eng)
    elif isinstance(model, models.Product):
        for eng in models.Engagement.objects.filter(product=model):
            add_risks_to_engagement(eng)
    elif isinstance(model, models.Engagement):
        add_risks_to_engagement(model)
    elif isinstance(model, models.Test):
        add_risks_to_engagement(model.engagement)
    else:
        for eng in models.Engagement.objects.all():
            add_risks_to_engagement(eng)

    return accepted
