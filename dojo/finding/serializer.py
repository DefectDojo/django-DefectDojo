from rest_framework import serializers


class IARecommendationSerializer(serializers.Serializer):
    status = serializers.CharField(required=False)
    data = serializers.JSONField()


class RecommendationSerializer(serializers.Serializer):
    like_status = serializers.BooleanField(required=False,
                                           allow_null=True,
                                           default=None)
    recommendations = serializers.ListField(child=serializers.CharField())
    mitigations = serializers.ListField(child=serializers.CharField())
    files_to_fix = serializers.ListField(child=serializers.CharField())

class FindingBulkUpdateSLAStartDateSerializer(serializers.Serializer):
    tags = serializers.CharField(max_length=200)
    date = serializers.DateField(required=False)