from rest_framework import serializers


class MetricsIARecommendationSerializers(serializers.Serializer):
    CHOICES_FIELD_EXCLUDE = [("findings", "findings"),]
    start_date = serializers.DateField(required=False, allow_null=True)
    end_date = serializers.DateField(required=False, allow_null=True)
    username = serializers.CharField(required=False, allow_null=True)
    exclude_field = serializers.ChoiceField(
            choices=CHOICES_FIELD_EXCLUDE,
            required=False,
            allow_null=True,
            error_messages={
                    "invalid_choice": "Invalid choice.Available options are: [findings]."
            }
    )
