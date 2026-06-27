from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

import dojo.risk_acceptance.helper as ra_helper
from dojo.finding.queries import get_authorized_findings
from dojo.models import Engagement, Finding
from dojo.notes.api.serializer import NoteSerializer
from dojo.risk_acceptance.models import Risk_Acceptance


class RiskAcceptanceProofSerializer(serializers.ModelSerializer):
    path = serializers.FileField(required=True)

    class Meta:
        model = Risk_Acceptance
        fields = ["path"]


class RiskAcceptanceToNotesSerializer(serializers.Serializer):
    risk_acceptance_id = serializers.PrimaryKeyRelatedField(
        queryset=Risk_Acceptance.objects.all(), many=False, allow_null=True,
    )
    notes = NoteSerializer(many=True)


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
        from dojo.engagement.api.serializer import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            EngagementSerializer,
        )
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
