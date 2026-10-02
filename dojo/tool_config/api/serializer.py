from rest_framework import serializers

from dojo.tool_config.models import Tool_Configuration


class ToolConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tool_Configuration
        fields = "__all__"
        extra_kwargs = {
            "password": {"write_only": True},
            "ssh": {"write_only": True},
            "api_key": {"write_only": True},
        }
