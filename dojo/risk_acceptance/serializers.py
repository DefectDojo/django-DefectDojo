from rest_framework import serializers


class RiskAcceptanceEmailSerializer(serializers.Serializer):
    permission_key = serializers.CharField(max_length=100,
                                  min_length=60,
                                  allow_blank=False,
                                  trim_whitespace=True)
