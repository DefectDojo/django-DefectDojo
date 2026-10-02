from rest_framework import serializers

from dojo.development_environment.models import Development_Environment


class DevelopmentEnvironmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Development_Environment
        fields = "__all__"
