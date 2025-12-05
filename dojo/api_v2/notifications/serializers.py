from rest_framework import serializers

class SerializerEmailNotificationRiskAcceptance(serializers.Serializer):
    recipients = serializers.ListField(child=serializers.CharField(), required=True)
    copy = serializers.EmailField(required=False, allow_blank=True)
    subject = serializers.CharField(required=True, max_length=255)
    message = serializers.CharField(required=False, allow_blank=True)
    template = serializers.CharField(required=False, allow_blank=True)
    is_async = serializers.BooleanField(required=False, default=True)
    risk_acceptance_id = serializers.IntegerField(required=False, default=True)
    enable_acceptance_risk_for_email = serializers.BooleanField(required=False, default=False) 
