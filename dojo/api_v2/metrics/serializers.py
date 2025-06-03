from rest_framework import serializers


class MetricsIARecommendationSerializers(serializers.Serializer):
    CHOICES_FIELD = [
        ("findings", "findings"),
        ]

    start_date = serializers.DateField(required=False, allow_null=True)
    final_date = serializers.DateField(required=False, allow_null=True)
    exclude_field = serializers.ChoiceField(
            choices=CHOICES_FIELD,
            required=False,
            allow_null=True,
    )
