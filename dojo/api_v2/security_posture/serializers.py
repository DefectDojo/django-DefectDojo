from rest_framework import serializers
from dojo.models import Engagement

class EngagementRequestSecuritypostureSerializer(serializers.Serializer):
    engagement_name = serializers.SlugRelatedField(
        slug_field='name',
        queryset=Engagement.objects.all(),
        required=False,
        allow_null=True
    )
    engagement_id = serializers.PrimaryKeyRelatedField(
        queryset=Engagement.objects.all(), many=False, required=False, allow_null=True,
    )

    def validate(self, data):
        engagement_id = data.get('engagement_id')
        engagement_name = data.get('engagement_name')
        
        if not engagement_id and not engagement_name:
            raise serializers.ValidationError(
                "Either engagement_id or engagement_name must be provided")
        
        return data

class EngagementEventSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField()
    description = serializers.CharField()

class EngagementEventsSerializer(serializers.Serializer):
    status = serializers.BooleanField()
    events = serializers.ListField(child=EngagementEventSerializer())

class EngagementSecuritypostureSerializer(serializers.Serializer):
    engagement_name = serializers.CharField(required=False)
    engagement_id = serializers.PrimaryKeyRelatedField(
        queryset=Engagement.objects.all(), many=False, allow_null=True,
    )
    severity_product = serializers.CharField(required=False, allow_null=True)
    adoption_devsecops = serializers.ListField(child=serializers.CharField())
    counter_active_findings = serializers.IntegerField()
    counter_very_critical = serializers.IntegerField()
    counter_critical = serializers.IntegerField()
    counter_high = serializers.IntegerField()
    counter_medium_low = serializers.IntegerField()
    counter_info = serializers.IntegerField()
    is_in_hacking_continuos = serializers.BooleanField(default=False)
    events_active_hacking = EngagementEventsSerializer()
    result = serializers.FloatField()
    status = serializers.CharField()
