from rest_framework import serializers


class IaRecommendationSerializer(serializers.Serializer):
    ia_recommendations = serializers.CharField(required=True)
