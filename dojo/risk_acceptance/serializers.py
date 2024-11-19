from rest_framework import serializers


class RiskAcceptanceEmailSerializer(serializers.Serializer):
    permission_key = serializers.CharField(max_length=100,
                                  min_length=60,
                                  allow_blank=False,
                                  trim_whitespace=True)

    actions = serializers.CharField(max_length=10,
                                    min_length=5,
                                    allow_blank=True,
                                    trim_whitespace=True)
