from rest_framework import serializers
from dojo.models import GeneralSettings


class GeneralSettingsSerializers(serializers.ModelSerializer):

    class Meta:
        model = GeneralSettings
        fields = "__all__"
 