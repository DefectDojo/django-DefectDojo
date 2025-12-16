from rest_framework import serializers


class IaRecommendationSerializer(serializers.Serializer):
    status = serializers.CharField(required=False)
    ia_recommendations = serializers.CharField(required=True)
