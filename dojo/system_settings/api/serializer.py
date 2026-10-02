from rest_framework import serializers

from dojo.system_settings.models import System_Settings


class SystemSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = System_Settings
        fields = "__all__"
