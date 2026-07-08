from rest_framework import serializers

from dojo.tool_type.models import Tool_Type


class ToolTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tool_Type
        fields = "__all__"

    def validate(self, data):
        if self.context["request"].method == "POST":
            name = data.get("name")
            # Make sure this will not create a duplicate test type
            if Tool_Type.objects.filter(name=name).count() > 0:
                msg = "A Tool Type with the name already exists"
                raise serializers.ValidationError(msg)
        return data
