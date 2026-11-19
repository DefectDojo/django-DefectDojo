from rest_framework import serializers
from dojo.api_v2.serializers import NoteSerializer
from dojo.models import Risk_Acceptance

class RiskAcceptanceToNotesSerializer(serializers.Serializer):
    risk_acceptance = serializers.PrimaryKeyRelatedField(
        queryset=Risk_Acceptance.objects.all(), many=False, allow_null=True,
    )
    notes = NoteSerializer(many=True)