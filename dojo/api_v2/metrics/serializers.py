from rest_framework import serializers


class MetricsIARecommendationSerializers(serializers.Serializer):
    start_date = serializers.DateField(required=False, allow_null=True)
    final_date = serializers.DateField(required=False, allow_null=True)