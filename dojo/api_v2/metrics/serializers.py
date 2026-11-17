from rest_framework import serializers
from dojo.models import Engagement


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


class MetricsDevicesWithoutFindingsFilterSerializer(serializers.Serializer):
    PROVIDER_CHOICES = (
        ("TENABLE", "TENABLE"),
        ("SERVERLESS", "SERVERLESS"),
        ("IMAGES", "IMAGES"),
    )

    provider = serializers.ChoiceField(
        choices=PROVIDER_CHOICES,
        required=False,
    )


class MetricsDevicesWithoutFindingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Engagement
        fields = (
            "name",
            "product_name",
            "product_type_name",
            "provider",
            "class_id",
            "item_class_id",
        )
