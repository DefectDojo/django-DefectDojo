from rest_framework import serializers


class IARecommendationSerializer(serializers.Serializer):
    status = serializers.CharField()
    data = serializers.JSONField()


class RecommendationSerializer(serializers.Serializer):
    recommendations = serializers.ListField(child=serializers.CharField())
    mitigations = serializers.ListField(child=serializers.CharField())
    files_to_fix = serializers.ListField(child=serializers.CharField())
