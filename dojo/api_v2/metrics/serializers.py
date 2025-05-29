from rest_framework import serializers


class MetricsIARecommendationSerializers(serializers.Serializer):
    start_date = serializers.DateField(required=False, allow_null=True)
    final_date = serializers.DateField(required=False, allow_null=True)
    group_by = serializers.ChoiceField(
        choices=['username', 'like', 'severity'],
        required=False,
        allow_null=True,
        default="none"
    )
    count = serializers.IntegerField(
        required=False,
        allow_null=True,
        default=10
    )
    order_by = serializers.ChoiceField(
        choices=['severity'],
        required=False,
        allow_null=True,
        default='count'
    )
