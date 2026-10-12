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

    def validate(self, data):
        # As on the edit page: stored credentials carry over only while the URL stays the same.
        if self.instance is not None and "url" in data and (data["url"] or "") != (self.instance.url or ""):
            for field in ("password", "ssh", "api_key"):
                if not data.get(field):
                    data[field] = None
        return super().validate(data)
