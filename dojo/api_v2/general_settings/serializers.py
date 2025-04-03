from rest_framework import serializers
from dojo.models import GeneralSettings


class GeneralSettingsSerializers(serializers.ModelSerializer):
    name_key = serializers.CharField(required=True)
    
    class Meta:
        model = GeneralSettings
        fields = "__all__"
