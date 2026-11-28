from rest_framework import serializers

from dojo.system_settings.models import System_Settings


class SystemSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = System_Settings
        fields = "__all__"

    def validate(self, attrs):
        attrs = super().validate(attrs)
        # DRF does not call Model.clean(), so apply the rules the settings page
        # applies. A PATCH carries only some fields: check the values the row
        # would hold after the save, the stored ones filling in the rest.
        values = {
            name: attrs.get(name, getattr(self.instance, name, None))
            for name in (
                "minimum_password_length",
                "maximum_password_length",
                "enable_deduplication",
                "false_positive_history",
                "retroactive_false_positive_history",
            )
        }
        errors = System_Settings.cross_field_errors(values)
        if errors:
            raise serializers.ValidationError(errors)
        return attrs
